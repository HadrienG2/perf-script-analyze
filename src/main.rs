//! This program wraps perf script and looks for fishy things in its output

use std::collections::HashSet;
use std::env;
use std::io::{BufRead, BufReader, Read, Result};
use std::process::{Command, Stdio};


/// Mechanism to extract individual samples from perf script's output
struct PerfSamples<Input: Read> {
    input: BufReader<Input>,
    buffer: String,
    header_len: usize,
    last_line_len: Option<usize>,
}
//
impl<Input: Read> PerfSamples<Input> {
    /// Initialize with a Rust reader plugging into the output of perf script
    /// (can be stdin, a pipe to a child process, a file... anything goes)
    pub fn new(input: Input) -> Self {
        Self {
            input: BufReader::new(input),
            buffer: String::new(),
            header_len: 0,
            last_line_len: None,
        }
    }

    // Reset the reader's state, to be invoked when moving to a new sample.
    fn reset(&mut self) {
        self.buffer.clear();
        self.header_len = 0;
        self.last_line_len = None;
    }

    /// Extract and decode the next sample from perf script's output, will
    /// return Ok(None) when the end of perf script's output is reached.
    pub fn next(&mut self) -> Result<Option<Sample>> {
        // Reset the internal state of the sample reader
        self.reset();

        // Load the first line of input. This is the sample's header, containing
        // info such as the executable name, PID, event type, etc.
        self.header_len = self.load_next_line()?;

        // Detect if the end of input was reached, if so report it to the caller
        if self.header_len == 0 {
            return Ok(None);
        }

        // Load input lines into the buffer until a newline or EOF is reached,
        // and record the position of the last useful byte in the buffer.
        let last_line_end = loop {
            let line_len = self.load_next_line()?;
            if line_len <= 1 {
                break self.buffer.len() - line_len;
            }
            self.last_line_len = Some(line_len);
        };

        // Extract the last stack frame of the sample, if any
        let buffer = &self.buffer;
        let last_stack_frame = self.last_line_len.map(move |last_line_len| {
            let last_line_start = last_line_end - last_line_len;
            &buffer[last_line_start..last_line_end]
        });

        // Return the decoded sample of data
        Ok(Some(Sample {
            raw_sample_data: &self.buffer[..last_line_end],
            header: &self.buffer[..self.header_len],
            stack_trace: &self.buffer[self.header_len..last_line_end],
            last_stack_frame,
        }))
    }

    /// Load the next line of input into the internal text buffer
    fn load_next_line(&mut self) -> Result<usize> {
        self.input.read_line(&mut self.buffer)
    }
}
///
///
/// This struct models one stack trace from perf script
#[derive(Debug)]
struct Sample<'a> {
    /// This is the raw sample data, if you need it for custom processing
    pub raw_sample_data: &'a str,

    /// Header of the sample, where infos like the process ID lie
    pub header: &'a str,

    /// Full stack trace of the sample, in textual form
    pub stack_trace: &'a str,

    /// Quick access to the last stack frame of the stack trace, if any
    pub last_stack_frame: Option<&'a str>,
}


/// Mechanism to analyze pre-parsed data samples and detect anomalies
struct SampleAnalyzer {
    /// These are the functions we expect to see at the end of stack traces
    expected_root_funcs: HashSet<&'static str>,

    /// These are the DSOs that we expect to see at the end of stack traces
    expected_root_dsos: HashSet<&'static str>,

    /// These "bad" DSOs are known to leave broken stack frames around, most
    /// likely because we don't have DWARF debugging info for them
    known_bad_dsos: HashSet<&'static str>,
}
//
impl SampleAnalyzer {
    /// Setup a sample analyzer
    pub fn new() -> Self {
        // These are the functions we expect to see on end of stack traces
        let mut expected_root_funcs = HashSet::new();
        expected_root_funcs.insert("_start");
        expected_root_funcs.insert("native_irq_return_iret");
        expected_root_funcs.insert("__libc_start_main");
        expected_root_funcs.insert("_dl_start_user");
        expected_root_funcs.insert("__clone");

        let mut expected_root_dsos = HashSet::new();
        expected_root_dsos.insert("([kernel.kallsyms])");
        expected_root_dsos.insert("(/usr/bin/perf)");

        // These DSOs are known to break stack traces (how evil of them!)
        let mut known_bad_dsos = HashSet::new();
        known_bad_dsos.insert("(/usr/lib64/xorg/modules/drivers/nvidia_drv.so)");
        known_bad_dsos.insert("(/usr/lib64/libGLX_nvidia.so.384.98)");
        known_bad_dsos.insert("(/usr/lib64/libGLX_nvidia.so.384.98)");

        // Return the analysis harness
        Self {
            expected_root_funcs,
            expected_root_dsos,
            known_bad_dsos,
        }
    }

    /// Classify a pre-parsed stack sample in various categories (see below)
    pub fn classify<'a>(&self, sample: &'a Sample) -> SampleCategory<'a> {
        // If there is no stack trace, report it
        let last_stack_frame = match sample.last_stack_frame {
            Some(last_line) => last_line,
            None => return SampleCategory::NoStackTrace,
        };

        // Split the last line into columns, ignoring whitespace
        let mut last_frame_columns = last_stack_frame.split_whitespace();

        // The first column is the instruction pointer for the last frame
        let last_instruction_pointer = last_frame_columns.next().unwrap();

        // The second column is the function name
        let last_function_name = last_frame_columns.next().unwrap();

        // The last column is the DSO name
        let last_dso = last_frame_columns.next().unwrap();

        // After that, there may be an optional "(deleted))" marker
        let opt_deleted = last_frame_columns.next();

        // If the top function or DSO matches our expectations, we're good
        if self.expected_root_dsos.contains(last_dso) ||
           self.expected_root_funcs.contains(last_function_name)
        {
            return SampleCategory::Normal;
        }

        // Otherwise, let us analyze it further. First, perf uses an IP which is
        // entirely composed of hex 'f's to denote incomplete DWARF stacks
        if last_instruction_pointer.len() % 8 == 0 &&
           last_instruction_pointer.chars().all(|c| c == 'f')
        {
            return SampleCategory::TruncatedStack;
        }

        // Perhaps the caller was JIT-compiled? Perf can detect this quite well.
        const JIT_START: &str = "(/tmp/perf-";
        const JIT_END: &str = ".map)";
        if last_dso.starts_with(JIT_START) && last_dso.ends_with(JIT_END) {
            let pid = &last_dso[JIT_START.len()..last_dso.len()-JIT_END.len()];
            let pid = pid.parse::<u32>().unwrap();
            return SampleCategory::JitCompiledBy(pid);
        }

        // Perf sometimes inserts strange "deleted" markers next to DSO names,
        // which are correlated with bad stack traces. I should investigate
        // these further, in the meantime I'll give them special treatment.
        if opt_deleted == Some("(deleted))") {
            return SampleCategory::DeletedByPerf;
        }

        // Perhaps it comes from a library that is known to break stack traces?
        // Let us try to find the last sensible DSO in the trace to check.
        let last_valid_dso =
            // Iterate over stack frames in reverse order
            sample.stack_trace.lines().rev()
                              // Find the DSO associated with each frame
                              .map(|frame| frame.split_whitespace()
                                                .rev()
                                                .next()
                                                .unwrap())
                              // Look for the first valid DSO in the stack trace
                              .skip_while(|&dso| dso == "([unknown])")
                              // Extract it and return it as an Option
                              .next();

        // Did we find a single sensible DSO in that stack?
        if let Some(valid_dso) = last_valid_dso {
            // Does it belong to our list of known-bad DSOs?
            let bad_dso_opt = self.known_bad_dsos.get(valid_dso);
            if let Some(bad_dso) = bad_dso_opt {
                // If so, report that to the user as the cause of the bad sample
                return SampleCategory::BrokenByBadDSO(bad_dso);
            }
        }

        // If the last DSO is "[unkown]", the stack trace is clearly broken, but
        // at this stage I am out of ideas as for how that could happen
        if last_dso == "([unknown])" {
            return SampleCategory::BrokenLastFrame;
        }

        // If the last DSO is valid, but the top function of the stack trace is
        // unexpected, it should be reported as a possible --max-stack-problem.
        SampleCategory::UnexpectedLastFunc(last_function_name)
    }
}
///
///
/// Output of SampleAnalyzer's evaluation of a perf sample's quality
#[derive(Debug)]
pub enum SampleCategory<'a> {
    /// This sample looks the way we expect, nothing special here.
    Normal,

    /// This sample has no strack trace attached to it.
    NoStackTrace,

    /// This sample most likely originates from a truncated DWARF stack.
    TruncatedStack,

    /// This sample was identified by perf as originating from a JIT compiler.
    /// The PID of the process which generated the code is attached.
    JitCompiledBy(u32),

    /// This sample's last DSO has a (deleted) marker. Perf sometimes adds them,
    /// I have no idea what they mean at this point in time.
    DeletedByPerf,

    /// This sample has a broken stack trace, which features a DSO that is known
    /// to be problematic. We still lost info, but at least we know why.
    BrokenByBadDSO(&'static str),

    /// The bottom of the stack trace is clearly broken for this sample, but
    /// it is not clear how that could happen.
    BrokenLastFrame,

    /// This sample has an unusual function at the top of the stack trace for no
    /// clear reason. You may want to check perf script's --max-stack parameter.
    UnexpectedLastFunc(&'a str),
}


/// Here be the main application logic
fn main() {
    // Let use run perf script with user-picked arguments
    let mut perf_script = Command::new("perf")
                                  .arg("script")
                                  .args(env::args().skip(1))
                                  .stdout(Stdio::piped())
                                  .spawn()
                                  .unwrap();

    // This struct fetches and decodes perf script data from stdin
    let mut samples = PerfSamples::new(perf_script.stdout.take().unwrap());

    // This struct will analyze and classify the samples
    let sample_analyzer = SampleAnalyzer::new();

    // We will aggregate statistics about the samples here
    let mut num_samples = 0usize;
    let mut num_normal_samples = 0usize;
    let mut num_stack_less_samples = 0usize;
    let mut num_truncated_stacks = 0usize;
    let mut num_jit_samples = 0usize;
    let mut num_deleted = 0usize;
    let mut num_bad_dsos = 0usize;
    let mut num_broken_last_frames = 0usize;
    let mut num_unexpected_last_func = 0usize;

    // Now, let's have a look at the parsed samples
    while let Some(sample) = samples.next().unwrap() {
        // Count the total amount of samples
        num_samples += 1;

        // Analyze incoming samples and aggregate some statistics
        use SampleCategory::*;
        match sample_analyzer.classify(&sample) {
            Normal => {
                num_normal_samples += 1;
                continue;
            },
            NoStackTrace => {
                num_stack_less_samples += 1;
                // print!("Sample without a stack trace:");
                continue;
            },
            TruncatedStack => {
                num_truncated_stacks += 1;
                // print!("Sample with a truncated stack:");
                continue;
            },
            JitCompiledBy(_pid) => {
                num_jit_samples += 1;
                // print!("JIT-compiled samples:");
                continue;
            },
            DeletedByPerf => {
                num_deleted += 1;
                // print!("Deleted samples:");
                continue;
            }
            BrokenByBadDSO(_dso) => {
                num_bad_dsos += 1;
                //print!("Sample broken by a known bad DSO:");
                continue;
            },
            BrokenLastFrame => {
                num_broken_last_frames += 1;
                // print!("Sample where the last frame is broken:");
                continue;
            },
            UnexpectedLastFunc(_name) => {
                num_unexpected_last_func += 1;
                // continue;
                print!("Sample with an unusual last function:");
            },
        }

        // Print the full sample data for the weirdest ones
        println!("\n{}", sample.raw_sample_data);
    }

    // Print a summary of sample statistics at the end
    println!();
    println!("Total samples: {}", num_samples);
    println!("- Normal data samples: {}", num_normal_samples);
    println!("- Samples without a stack trace: {}", num_stack_less_samples);
    println!("- Truncated DWARF stacks: {}", num_truncated_stacks);
    println!("- JIT-compiled samples: {}", num_jit_samples);
    println!("- Deleted samples: {}", num_deleted);
    println!("- Stack trace broken by a bad DSO: {}", num_bad_dsos);
    println!("- Samples with broken last frame: {}", num_broken_last_frames);
    println!("- Samples with unusual last frame: {}", num_unexpected_last_func);

    // Wait for the execution of perf script to complete
    perf_script.wait().unwrap();
}
