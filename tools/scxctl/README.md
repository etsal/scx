# scxctl

[![crates.io](https://img.shields.io/crates/v/scxctl.svg)](https://crates.io/crates/scxctl)
[![license](https://img.shields.io/crates/l/scxctl.svg)](https://crates.io/crates/scxctl)

`scxctl` is a cli dbus client for interacting with `scx_loader`.

## Features

- Get the current scheduler and mode
- List all available schedulers
- Start a scheduler in a given mode, or with given arguments
- Switch between schedulers and modes
- Stop the running scheduler
- Restart the running scheduler

## Installation

`scxctl` can be installed from crates.io through cargo

```
cargo install scxctl
```

## Usage

```
$ scxctl --help
Usage: scxctl <COMMAND>

Commands:
  get     Get the current scheduler and mode
  list    List all supported schedulers
  start   Start a scheduler in a mode or with arguments
  switch  Switch schedulers or modes, optionally with arguments
  stop    Stop the current scheduler
  restart Restart the current scheduler with original configuration
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```
$ scxctl start --help
Start a scheduler in a mode or with arguments

Usage: scxctl start [OPTIONS] --sched <SCHED>

Options:
  -s, --sched <SCHED>  Scheduler to start
  -m, --mode <MODE>    Mode to start in [default: auto] [possible values: auto, gaming, powersave, lowlatency, server]
  -a, --args <ARGS>    Arguments to run scheduler with
  -h, --help           Print help
```

```
$ scxctl switch --help
Switch schedulers or modes, optionally with arguments

Usage: scxctl switch [OPTIONS]

Options:
  -s, --sched <SCHED>  Scheduler to switch to
  -m, --mode <MODE>    Mode to switch to [possible values: auto, gaming, powersave, lowlatency, server]
  -a, --args <ARGS>    Arguments to run scheduler with
  -h, --help           Print help
```

### Examples:

Start bpfland in auto mode

```
scxctl start -s bpfland
```

Switch to gaming mode

```
scxctl switch -m gaming
```

Switch to lavd with verbose and performance flags

```
scxctl switch -s lavd -a="-v,--performance"
```

Switch to flash and increase the maximum time slice from 4ms (default) to 20ms

```
scxctl switch -s flash -a="-s,20000"
```
