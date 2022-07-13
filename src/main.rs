extern crate capstone;

use capstone::prelude::*;
use object::{Object, ObjectSection};
use std::env;
use std::fs;

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    if args.len() != 2 {
        println!("You should pass exactly one argument as the input binary. Abort.");
        return;
    }
    let input_prog = fs::read(&args[1]).expect("Something went wrong when reading the file");
    let obj_file = object::File::parse(&*input_prog).expect("Can read the elf file");
    let data = obj_file.section_by_name(".text").unwrap();
    let data: &[u8] = data.data().unwrap();

    // Create Capston reader
    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    // Disasembly
    let insns = cs
        .disasm_all(data, 0x1000)
        .expect("Failed to disassemble");
    println!("Found {} instructions", insns.len());
    for i in insns.as_ref() {
        println!();
        println!("{}", i);

        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
            ("read regs:", reg_names(&cs, detail.regs_read())),
            ("write regs:", reg_names(&cs, detail.regs_write())),
            ("insn groups:", group_names(&cs, detail.groups())),
        ];

        for &(ref name, ref message) in output.iter() {
            println!("{:4}{:12} {}", "", name, message);
        }

        println!("{:4}operands: {}", "", ops.len());
        for op in ops {
            println!("{:8}{:?}", "", op);
        }
    }
}
