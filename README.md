A graphical interface for performing lexical analysis on Z-Language source code.

Overview
• The Z-Language Lexer UI provides an easy-to-use Tkinter-based interface that allows users to:
• Load .txt or .z source files
• Analyze code and generate tokens
• View tokens in a table (type, lexeme, line number)
• Export results to CSV
• Clear and re-run analysis anytime

Features
• Modern Blue-Themed UI using Tkinter + ttk
• Real-time Lexical Analysis powered by a custom Lexer
• Supports keywords, identifiers, numbers, operators, delimiters, strings, and comments
• Scrollable token table for large inputs
• CSV export for documentation or debugging
• Error detection for unexpected symbols or unterminated strings

How to Use
1.) Run the script:
python "Z Lexer UI.py"
2.) Click Load File to import a Z-Language source file
3.) Click Analyze to tokenize the code
4.) View tokens in the table
5.) Click Export CSV to save results
6.) Click Clear to remove inputs and start fresh

File Types Supported
.zlang

Requirements
• Python 3.8+
• Tkinter (bundled with most Python installations)
• No external libraries are required.
