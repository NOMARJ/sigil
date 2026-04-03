// This file simulates the issue in node_modules/.pnpm/iconv-lite@0.7.1/node_modules/iconv-lite/encodings/sbcs-data.js
// It contains Unicode box-drawing characters around byte position 200 to test the boundary fix

module.exports = {
    // Single Byte Character Set encodings data
    // This is a long line that approaches the 200-byte truncation boundary where Unicode chars will be ────────────────────────────────────────
    
    // The box drawing characters above (─) are multi-byte UTF-8 and will cause panic if sliced unsafely
    cp1252: [
        null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
        null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
        0x20ac, null, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039,
        0x0152, null, 0x017d, null, null, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
        0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, null, 0x017e, 0x0178
    ],
    
    // More Unicode chars near boundary: ░▒▓█▀▄▌▐▬▲▼◄►♠♣♥♦
    iso88591: "ISO-8859-1 encoding with more Unicode boundary tests ────────────────────────────────────",
    
    // eval() pattern to trigger security scan
    dangerousCode: function() {
        eval("console.log('This should be flagged by security scanner')");
        return "┌─┐│ │└─┘"; // Unicode box drawing chars
    }
};