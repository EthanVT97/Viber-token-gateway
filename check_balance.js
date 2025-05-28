const fs = require("fs");

if (process.argv.length < 3) {
  console.error("Usage: node check_balance.js <file.js>");
  process.exit(1);
}

const filename = process.argv[2];
const content = fs.readFileSync(filename, "utf8");

const pairs = {
  "{": "}",
  "(": ")",
  "[": "]",
};

const stack = [];
const linePositions = [];

let line = 1;

for (let i = 0; i < content.length; i++) {
  const char = content[i];

  if (char === "\n") {
    line++;
    continue;
  }

  if (char in pairs) {
    stack.push({ char, line });
  } else if (Object.values(pairs).includes(char)) {
    if (stack.length === 0) {
      console.error(`Unmatched closing '${char}' at line ${line}`);
      process.exit(1);
    }
    const last = stack.pop();
    if (pairs[last.char] !== char) {
      console.error(
        `Mismatched '${last.char}' opened at line ${last.line} and '${char}' at line ${line}`
      );
      process.exit(1);
    }
  }
}

if (stack.length > 0) {
  stack.forEach(({ char, line }) => {
    console.error(`Unclosed '${char}' opened at line ${line}`);
  });
  process.exit(1);
}

console.log("All brackets are balanced.");
