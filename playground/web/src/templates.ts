import type { Language } from './types';

export const languageLabels: Record<Language, string> = {
  c: 'C',
  cpp: 'C++',
  rust: 'Rust',
  go: 'Go',
  java: 'Java',
  python: 'Python',
  node: 'Node.js',
};

export const languageFiles: Record<Language, string> = {
  c: 'main.c',
  cpp: 'main.cpp',
  rust: 'main.rs',
  go: 'main.go',
  java: 'Main.java',
  python: 'main.py',
  node: 'main.js',
};

export const monacoLanguages: Record<Language, string> = {
  c: 'c',
  cpp: 'cpp',
  rust: 'rust',
  go: 'go',
  java: 'java',
  python: 'python',
  node: 'javascript',
};

export const templates: Record<Language, string> = {
  rust: `use std::io::{self, Read};

fn solve(question: &str) -> String {
    // TODO: parse the CogGate challenge and return base64url without padding.
    let _ = question;
    String::new()
}

fn main() {
    let mut question = String::new();
    io::stdin().read_to_string(&mut question).unwrap();
    println!("{}", solve(&question));
}
`,
  go: `package main

import (
    "fmt"
    "io"
    "os"
)

func solve(question string) string {
    // TODO: return base64url without padding.
    return ""
}

func main() {
    input, _ := io.ReadAll(os.Stdin)
    fmt.Println(solve(string(input)))
}
`,
  java: `import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Main {
    static String solve(String question) {
        // TODO: return base64url without padding.
        return "";
    }

    public static void main(String[] args) throws IOException {
        String question = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
        System.out.println(solve(question));
    }
}
`,
  python: `import sys


def solve(question: str) -> str:
    # TODO: return base64url without padding.
    return ""


if __name__ == "__main__":
    print(solve(sys.stdin.read()))
`,
  node: `function solve(question) {
  // TODO: return base64url without padding.
  return '';
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => console.log(solve(input)));
`,
  c: `#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // TODO: read the challenge from stdin and print base64url without padding.
    char buffer[4096];
    while (fgets(buffer, sizeof buffer, stdin) != NULL) {
        /* parse input */
    }
    puts("");
    return 0;
}
`,
  cpp: `#include <iostream>
#include <iterator>
#include <string>

std::string solve(const std::string& question) {
    // TODO: return base64url without padding.
    return {};
}

int main() {
    const std::string question{
        std::istreambuf_iterator<char>{std::cin},
        std::istreambuf_iterator<char>{}
    };
    std::cout << solve(question) << '\\n';
}
`,
};
