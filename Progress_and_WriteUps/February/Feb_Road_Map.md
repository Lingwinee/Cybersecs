Since you’re a CS student with C/C++ experience, binary exploitation is a good focus — but you need a **tight foundation first**.
Here’s a **1-Month Roadmap (Beginner → Intro to Binary Exploitation)**.

---

# 🎯 Month Goal

Understand:

* How programs run in memory
* How vulnerabilities happen in C
* Basic stack-based exploitation

---

# 📅 Week 1 — Foundations (Very Important)

## 1️⃣ Linux Basics

You must be comfortable with:

* `ls`, `cd`, `grep`, `cat`
* `chmod`, `chown`
* `gdb`
* `gcc`

👉 Install:

* Ubuntu (VM or WSL)
* VS Code + C debugger
* `gdb`
* `pwntools`

---

## 2️⃣ C Memory Model (Critical)

Understand deeply:

* Stack vs Heap
* Function call stack
* Pointers
* Arrays
* Buffer overflow concept

### Practice:

```c
#include <stdio.h>

void vuln() {
    char buffer[16];
    gets(buffer);   // dangerous
}

int main() {
    vuln();
    return 0;
}
```

Compile without protections:

```bash
gcc -m32 -fno-stack-protector -z execstack -no-pie vuln.c -o vuln
```

Learn:

* What is stored in stack?
* What is return address?
* How overflow overwrites return address?

---

# 📅 Week 2 — Assembly & Debugging

## 1️⃣ x86 Assembly Basics

Learn:

* Registers: `eax`, `ebx`, `esp`, `ebp`
* `mov`, `push`, `pop`, `call`, `ret`
* Stack frame structure

Use:

```bash
gdb ./vuln
disassemble main
```

Practice:

* Step through instructions
* Observe stack changes
* Inspect memory (`x/20x $esp`)

---

## 2️⃣ Learn GDB Properly

Commands:

* `break`
* `run`
* `next`
* `step`
* `info registers`
* `x`

Goal:
Understand what happens when function returns.

---

# 📅 Week 3 — Real Binary Exploitation Concepts

Now we go real.

## 1️⃣ Buffer Overflow Exploit

Concepts:

* Overwriting return address
* Finding offset
* Controlling execution

Use:

```bash
python3 -c "print('A'*100)"
```

Understand:

* Segmentation fault
* EIP overwrite

---

## 2️⃣ Protections

Learn:

* ASLR
* NX
* PIE
* Stack Canary

Check:

```bash
checksec ./vuln
```

Understand what each protection prevents.

---

# 📅 Week 4 — Practical Exploitation

## 1️⃣ Ret2Win Challenge

Find binary with hidden function like:

```c
void win() {
    system("/bin/sh");
}
```

Goal:
Overwrite return address to jump to `win`.

---

## 2️⃣ Start CTF Practice

Use:

* picoCTF
* OverTheWire (Bandit → then Narnia)
* pwn.college

Solve at least:

* 5 beginner pwn challenges

---

# 📚 Daily Study Structure (2–3 Hours)

1. 30m theory
2. 1h coding/debugging
3. 30m exploitation practice
4. 30m write notes

---

# 🧠 Concepts You Must Understand Clearly

* How stack grows
* What happens during `call`
* What `ret` does
* Memory addresses
* Little endian
* Why `gets()` is dangerous

If you don’t understand these, exploitation won’t click.

---

# 🛠 Tools You Should Learn

* `gdb`
* `pwntools`
* `objdump`
* `checksec`
* `strings`

---

# 🚀 After This Month

Next topics:

* Format string bugs
* Heap exploitation
* ROP (Return Oriented Programming)
* Shellcode writing

---
