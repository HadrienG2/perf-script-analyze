//! This program wraps perf script and looks for fishy things in its output

use std::collections::HashSet;
use std::env;
use std::io::{BufRead, BufReader, Read, Result};
use std::process::{Command, Stdio};


/// Mechanism to extract individual data samples from perf script's output
struct PerfSamples<Input: Read> {
    input: BufReader<Input>,
    buffer: String,
    header_len: usize,
    last_line_len: Option<usize>,
}
//
impl<Input: Read> PerfSamples<Input> {
    /// Initialize with a Rust reader plugging into the output of perf script
    /// (can be stdin, a pipe to a child process... anything goes)
    pub fn new(input: Input) -> Self {
        Self {
            input: BufReader::new(input),
            buffer: String::new(),
            header_len: 0,
            last_line_len: None,
        }
    }

    // Reset the reader's state (to be invoked when moving to a new sample)
    fn reset(&mut self) {
        self.buffer.clear();
        self.header_len = 0;
        self.last_line_len = None;
    }

    /// Extract and decode the next sample from perf script's output
    pub fn next(&mut self) -> Result<Option<Sample>> {
        // Reset the internal state of the sample reader
        self.reset();

        // Load the first line of input. This is the sample's header, containing
        // info such as the executable name, PID, event type, etc.
        self.header_len = self.load_next_line()?;

        // Detect if the end of input was reached, and report it to the caller
        if self.header_len == 0 {
            return Ok(None);
        }

        // Load input lines into the buffer until a newline or EOF is reached
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
            call_stack: &self.buffer[self.header_len..last_line_end],
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
/// This struct models one call stack sample from perf script
#[derive(Debug)]
struct Sample<'a> {
    /// This is the raw sample data, if you need it for debugging purposes
    pub raw_sample_data: &'a str,

    /// Header of the sample, where infos like the process ID lie
    pub header: &'a str,

    /// Full call stack of the sample, in textual form
    pub call_stack: &'a str,

    /// Quick access to the last stack frame of the call stack, if any
    pub last_stack_frame: Option<&'a str>,
}


/// Mechanism to analyze data samples and detect anomalies
struct SampleAnalyzer {
    /// These are the functions which we expect to see at the top of call stacks
    expected_top_funcs: HashSet<&'static str>,

    /// These "bad" DSOs are known to leave broken stack frames around, most
    /// likely because we don't have DWARF debugging info for them
    known_bad_dsos: HashSet<&'static str>,
}
//
impl SampleAnalyzer {
    /// Setup a sample analyzer
    pub fn new() -> Self {
        // These are the functions we expect to see on top of call stacks
        let mut expected_top_funcs = HashSet::new();
        expected_top_funcs.insert("_start");
        expected_top_funcs.insert("native_irq_return_iret");
        expected_top_funcs.insert("entry_SYSCALL_64_fastpath");
        expected_top_funcs.insert("syscall_return_via_sysret");
        expected_top_funcs.insert("__libc_start_main");
        expected_top_funcs.insert("_dl_start_user");
        expected_top_funcs.insert("__clone");

        // These DSOs are known to break stack traces (how evil of them!)
        let mut known_bad_dsos = HashSet::new();
        known_bad_dsos.insert("(/usr/lib64/xorg/modules/drivers/nvidia_drv.so)");
        known_bad_dsos.insert("(/usr/lib64/libGLX_nvidia.so.384.98)");

        // Return the analysis harness
        Self {
            expected_top_funcs,
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

        // The first column is the instruction pointer, we don't need it
        let last_instruction_pointer = last_frame_columns.next().unwrap();

        // The second column is the function name, which is what we're after
        let last_function_name = last_frame_columns.next().unwrap();

        // If the top function matches our expectations, we're good
        if self.expected_top_funcs.contains(last_function_name) {
            return SampleCategory::Normal;
        }

        // Otherwise, let us analyze it further. First, perf uses an IP which is
        // entirely composed of hex 'f's to denote incomplete DWARF stacks
        if last_instruction_pointer.chars().all(|c| c == 'f') {
            return SampleCategory::TruncatedStack;
        }

        // Perhaps the caller was JIT-compiled? Perf can detect this quite well.
        let last_dso = last_frame_columns.next().unwrap();
        const JIT_START: &str = "(/tmp/perf-";
        const JIT_END: &str = ".map)";
        if last_dso.starts_with(JIT_START) && last_dso.ends_with(JIT_END) {
            let pid = &last_dso[JIT_START.len()..last_dso.len()-JIT_END.len()];
            let pid = pid.parse::<u32>().unwrap();
            return SampleCategory::JitCompiledBy(pid);
        }

        // Perhaps it comes from a library known to break call stacks?
        // Let us try to find the last sensible DSO in the call stack
        let last_valid_dso =
            // Iterate over stack frames in reverse order
            sample.call_stack.lines().rev()
                             // Find the DSO associated with each frame
                             .map(|frame| frame.split_whitespace()
                                               .rev()
                                               .next()
                                               .unwrap())
                             // Look for the first valid DSO in the call stack
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

        // Sorry, I have no idea about what's going on :(
        SampleCategory::UnexpectedTopFunc(last_function_name)
    }
}
///
///
/// Output of SampleAnalyzer's evaluation of a perf sample's quality
#[derive(Debug)]
pub enum SampleCategory<'a> {
    /// This sample looks the way we expect, nothing special here.
    Normal,

    /// This sample has no call stack attached to it.
    NoStackTrace,

    /// This sample most likely originates from a truncated DWARF stack.
    TruncatedStack,

    /// This sample was identified by perf as originating from a JIT compiler.
    /// The PID of the process which generated the code is attached.
    JitCompiledBy(u32),

    /// This sample has a broken call stack, which features a DSO that is known
    /// to be problematic. We still lost info, but at least we know why.
    BrokenByBadDSO(&'static str),

    /// This sample has an unusual function at the top of the call stack for no
    /// clear reason. You may want to check perf script's --max-stack parameter.
    /// I also _think_ that perf can get confused by constructors and
    /// destructors of static objects sometimes, but don't quote me on this.
    UnexpectedTopFunc(&'a str),
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
    let mut num_bad_dsos = 0usize;
    let mut num_unexpected_samples = 0usize;

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
                continue;
            },
            TruncatedStack => {
                num_truncated_stacks += 1;
                continue;
            },
            JitCompiledBy(_pid) => {
                num_jit_samples += 1;
                continue;
            },
            BrokenByBadDSO(_dso) => {
                num_bad_dsos += 1;
                continue;
            }
            UnexpectedTopFunc(_name) => {
                num_unexpected_samples += 1;
                print!("Sample with an unusual top frame:");
            },
        }

        // Print the full sample data for the weirdest ones
        println!("\n{}", sample.raw_sample_data);
    }

    // Print a summary of sample statistics at the end
    println!();
    println!("Total samples: {}", num_samples);
    println!("- Normal data samples: {}", num_normal_samples);
    println!("- Samples without a call stack: {}", num_stack_less_samples);
    println!("- Truncated DWARF stacks: {}", num_truncated_stacks);
    println!("- JIT-compiled samples: {}", num_jit_samples);
    println!("- Call stack broken by a bad DSO: {}", num_bad_dsos);
    println!("- Samples with an unusual top frame: {}", num_unexpected_samples);

    // Wait for the execution of perf script to complete
    perf_script.wait().unwrap();
}
