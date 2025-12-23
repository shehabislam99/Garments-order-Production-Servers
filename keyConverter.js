const fs = require("fs");
const jsonData = fs.readFileSync("./textile-flow-key.json","utf-8");

const base64 = Buffer.from(jsonData).toString("base64");
console.log(base64);
