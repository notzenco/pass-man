//! Desktop entry point. Delegates to the library so the same commands are
//! testable and usable from both the binary and the mobile entry points.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    pass_man_desktop_lib::run();
}
