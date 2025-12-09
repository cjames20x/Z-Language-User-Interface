#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import os
from enum import Enum, auto
from PIL import Image, ImageTk

# ---------------------- THEMES ---------------------- #
def apply_light_theme(root):
    """Apply light theme to the GUI."""
    style = ttk.Style(root)
    style.theme_use("default")

    primary = "#1E90FF"
    dark_primary = "#1C86EE"
    bg = "#E6F0FF"

    root.configure(bg=bg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground="black", font=("Segoe UI", 10))
    style.configure("TButton", background=primary, foreground="white", padding=8, font=("Segoe UI", 10, "bold"))
    style.map("TButton", background=[("active", dark_primary)], foreground=[("active", "white")])
    style.configure("Treeview", background="white", foreground="black", fieldbackground="white", rowheight=24, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background=primary, foreground="white", font=("Segoe UI", 10, "bold"))

def apply_dark_theme(root):
    """Apply dark theme to the GUI."""
    style = ttk.Style(root)
    style.theme_use("default")

    bg = "#1E1E1E"
    fg = "#FFFFFF"
    btn = "#3A3A3A"
    btn_active = "#505050"

    root.configure(bg=bg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
    style.configure("TButton", background=btn, foreground=fg, padding=8, font=("Segoe UI", 10, "bold"))
    style.map("TButton", background=[("active", btn_active)], foreground=[("active", fg)])
    style.configure("Treeview", background="#2B2B2B", foreground=fg, fieldbackground="#2B2B2B", rowheight=24, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background="#3A3A3A", foreground=fg, font=("Segoe UI", 10, "bold"))

# ---------------------- TOKEN ENUM ---------------------- #
class TokenType(Enum):
    """All token types for Z-Language."""
    TOKEN_TYPE_NULL = -1
    TOKEN_IDENTIFIER = auto()
    TOKEN_COMMENT = auto()
    TOKEN_OP_PLUS = auto()
    TOKEN_OP_MINUS = auto()
    TOKEN_OP_MULTIPLY = auto()
    TOKEN_OP_DIVIDE = auto()
    TOKEN_OP_MODULO = auto()
    TOKEN_OP_ASSIGN = auto()
    TOKEN_OP_PLUS_ASSIGN = auto()
    TOKEN_OP_MINUS_ASSIGN = auto()
    TOKEN_OP_MULTIPLY_ASSIGN = auto()
    TOKEN_OP_DIVIDE_ASSIGN = auto()
    TOKEN_OP_MOD_ASSIGN = auto()
    TOKEN_OP_XOR_ASSIGN = auto()
    TOKEN_OP_AND_ASSIGN = auto()
    TOKEN_OP_OR_ASSIGN = auto()
    TOKEN_OP_LESS = auto()
    TOKEN_OP_GREATER = auto()
    TOKEN_OP_LESS_EQUAL = auto()
    TOKEN_OP_GREATER_EQUAL = auto()
    TOKEN_OP_EQUAL = auto()
    TOKEN_OP_NOT_EQUAL = auto()
    TOKEN_OP_NOT = auto()
    TOKEN_OP_AND = auto()
    TOKEN_OP_OR = auto()
    TOKEN_OP_INCREMENT = auto()
    TOKEN_OP_DECREMENT = auto()
    TOKEN_KEYWORD_ALIAS = auto()
    TOKEN_KEYWORD_BLEND = auto()
    TOKEN_KEYWORD_BOOL = auto()
    TOKEN_KEYWORD_BOUNCE = auto()
    TOKEN_KEYWORD_CAP = auto()
    TOKEN_KEYWORD_CASE = auto()
    TOKEN_KEYWORD_CORE = auto()
    TOKEN_KEYWORD_DECI = auto()
    TOKEN_KEYWORD_DOUBLE = auto()
    TOKEN_KEYWORD_DROP = auto()
    TOKEN_KEYWORD_ELSE = auto()
    TOKEN_KEYWORD_EMOJI = auto()
    TOKEN_KEYWORD_EMPTY = auto()
    TOKEN_KEYWORD_ENUM = auto()
    TOKEN_KEYWORD_FAM = auto()
    TOKEN_KEYWORD_FIXED = auto()
    TOKEN_KEYWORD_FOR = auto()
    TOKEN_KEYWORD_GRAB = auto()
    TOKEN_KEYWORD_IF = auto()
    TOKEN_KEYWORD_IMPORT = auto()
    TOKEN_KEYWORD_LENGTH = auto()
    TOKEN_KEYWORD_LETT = auto()
    TOKEN_KEYWORD_MAXI = auto()
    TOKEN_KEYWORD_MINI = auto()
    TOKEN_KEYWORD_MATIC = auto()
    TOKEN_KEYWORD_NEXT = auto()
    TOKEN_KEYWORD_NOCAP = auto()
    TOKEN_KEYWORD_NORM = auto()
    TOKEN_KEYWORD_NUMBS = auto()
    TOKEN_KEYWORD_OUT = auto()
    TOKEN_KEYWORD_SHADY = auto()
    TOKEN_KEYWORD_SPILL = auto()
    TOKEN_KEYWORD_STAY = auto()
    TOKEN_KEYWORD_STRUCT = auto()
    TOKEN_KEYWORD_SWIM = auto()
    TOKEN_KEYWORD_SWITCH = auto()
    TOKEN_KEYWORD_TAG = auto()
    TOKEN_KEYWORD_TEXT = auto()
    TOKEN_KEYWORD_VIBE = auto()
    TOKEN_KEYWORD_WHILE = auto()
    TOKEN_KEYWORD_ZAVED = auto()
    TOKEN_FUNCTION_AVG = auto()
    TOKEN_FUNCTION_ASCENDING = auto()
    TOKEN_FUNCTION_DESCENDING = auto()
    TOKEN_FUNCTION_MAX = auto()
    TOKEN_FUNCTION_MIN = auto()
    TOKEN_FUNCTION_FINDSTRING = auto()
    TOKEN_DELIMITER_SEMICOLON = auto()
    TOKEN_DELIMITER_LPAREN = auto()
    TOKEN_DELIMITER_RPAREN = auto()
    TOKEN_DELIMITER_LBRACE = auto()
    TOKEN_DELIMITER_RBRACE = auto()
    TOKEN_DELIMITER_LBRACKET = auto()
    TOKEN_DELIMITER_RBRACKET = auto()
    TOKEN_DELIMITER_COMMA = auto()
    TOKEN_DELIMITER_QUOTE = auto()
    TOKEN_ERROR = auto()
    TOKEN_EOF = auto()

# Mapping enum to string for display
TOKEN_TYPE_TO_STRING = {t: t.name for t in TokenType}

# Keywords mapping
KEYWORDS = {
    "alias": TokenType.TOKEN_KEYWORD_ALIAS,
    "blend": TokenType.TOKEN_KEYWORD_BLEND,
    "bool": TokenType.TOKEN_KEYWORD_BOOL,
    "bounce": TokenType.TOKEN_KEYWORD_BOUNCE,
    "cap": TokenType.TOKEN_KEYWORD_CAP,
    "case": TokenType.TOKEN_KEYWORD_CASE,
    "core": TokenType.TOKEN_KEYWORD_CORE,
    "deci": TokenType.TOKEN_KEYWORD_DECI,
    "double": TokenType.TOKEN_KEYWORD_DOUBLE,
    "drop": TokenType.TOKEN_KEYWORD_DROP,
    "else": TokenType.TOKEN_KEYWORD_ELSE,
    "emoji": TokenType.TOKEN_KEYWORD_EMOJI,
    "empty": TokenType.TOKEN_KEYWORD_EMPTY,
    "enum": TokenType.TOKEN_KEYWORD_ENUM,
    "fam": TokenType.TOKEN_KEYWORD_FAM,
    "fixed": TokenType.TOKEN_KEYWORD_FIXED,
    "for": TokenType.TOKEN_KEYWORD_FOR,
    "grab": TokenType.TOKEN_KEYWORD_GRAB,
    "if": TokenType.TOKEN_KEYWORD_IF,
    "import": TokenType.TOKEN_KEYWORD_IMPORT,
    "length": TokenType.TOKEN_KEYWORD_LENGTH,
    "lett": TokenType.TOKEN_KEYWORD_LETT,
    "maxi": TokenType.TOKEN_KEYWORD_MAXI,
    "mini": TokenType.TOKEN_KEYWORD_MINI,
    "matic": TokenType.TOKEN_KEYWORD_MATIC,
    "next": TokenType.TOKEN_KEYWORD_NEXT,
    "nocap": TokenType.TOKEN_KEYWORD_NOCAP,
    "norm": TokenType.TOKEN_KEYWORD_NORM,
    "numbs": TokenType.TOKEN_KEYWORD_NUMBS,
    "out": TokenType.TOKEN_KEYWORD_OUT,
    "shady": TokenType.TOKEN_KEYWORD_SHADY,
    "spill": TokenType.TOKEN_KEYWORD_SPILL,
    "stay": TokenType.TOKEN_KEYWORD_STAY,
    "struct": TokenType.TOKEN_KEYWORD_STRUCT,
    "swim": TokenType.TOKEN_KEYWORD_SWIM,
    "switch": TokenType.TOKEN_KEYWORD_SWITCH,
    "tag": TokenType.TOKEN_KEYWORD_TAG,
    "text": TokenType.TOKEN_KEYWORD_TEXT,
    "vibe": TokenType.TOKEN_KEYWORD_VIBE,
    "while": TokenType.TOKEN_KEYWORD_WHILE,
    "zaved": TokenType.TOKEN_KEYWORD_ZAVED,
    "avg": TokenType.TOKEN_FUNCTION_AVG,
    "ascending": TokenType.TOKEN_FUNCTION_ASCENDING,
    "descending": TokenType.TOKEN_FUNCTION_DESCENDING,
    "max": TokenType.TOKEN_FUNCTION_MAX,
    "min": TokenType.TOKEN_FUNCTION_MIN,
    "findstring": TokenType.TOKEN_FUNCTION_FINDSTRING,
}

# ---------------- TOKEN CLASS ---------------- #
class Token:
    """Represents a single token in source code."""
    def __init__(self, type_, lexeme, line):
        self.type = type_
        self.lexeme = lexeme
        self.line = line

# ---------------------- LEXER ---------------------- #
class Lexer:
    """Lexical analyzer for Z-Language."""
    def __init__(self, source):
        self.source = source
        self.start = 0
        self.current = 0
        self.line = 1
        self.token_start_line = 1

    def is_at_end(self):
        return self.current >= len(self.source)

    def next_char(self):
        c = self.source[self.current]
        self.current += 1
        return c

    def peek(self):
        return '\0' if self.is_at_end() else self.source[self.current]

    def peek_next(self):
        return '\0' if self.current + 1 >= len(self.source) else self.source[self.current + 1]

    def match(self, expected):
        if self.is_at_end() or self.source[self.current] != expected:
            return False
        self.current += 1
        return True

    def skip_whitespace(self):
        while True:
            c = self.peek()
            if c in (' ', '\r', '\t'):
                self.next_char()
            elif c == '\n':
                self.line += 1
                self.next_char()
            else:
                break

    def make_token(self, ttype):
        lex = self.source[self.start:self.current]
        return Token(ttype, lex, self.token_start_line)

    def error_token(self, msg):
        return Token(TokenType.TOKEN_ERROR, msg, self.line)

    def handle_string(self):
        while self.peek() != '"' and not self.is_at_end():
            if self.peek() == '\n': self.line += 1
            self.next_char()
        if self.is_at_end(): return self.error_token("Unterminated string")
        self.next_char()
        return Token(TokenType.TOKEN_KEYWORD_TEXT, self.source[self.start:self.current], self.token_start_line)

    def handle_number(self):
        while self.peek().isdigit():
            self.next_char()
        if self.peek() == '.' and self.peek_next().isdigit():
            self.next_char()
            while self.peek().isdigit():
                self.next_char()
            return Token(TokenType.TOKEN_KEYWORD_SWIM, self.source[self.start:self.current], self.token_start_line)
        return Token(TokenType.TOKEN_KEYWORD_NUMBS, self.source[self.start:self.current], self.token_start_line)

    def handle_comment(self):
        while self.peek() != '\n' and not self.is_at_end():
            self.next_char()
        return Token(TokenType.TOKEN_COMMENT, self.source[self.start:self.current], self.token_start_line)

    def scan_token(self):
        self.skip_whitespace()
        self.start = self.current
        self.token_start_line = self.line
        if self.is_at_end():
            return Token(TokenType.TOKEN_EOF, "", self.line)

        c = self.next_char()

        # Identifiers & Keywords
        if c.isalpha() or c == '_':
            while self.peek().isalnum() or self.peek() == '_':
                self.next_char()
            text = self.source[self.start:self.current]
            return Token(KEYWORDS.get(text, TokenType.TOKEN_IDENTIFIER), text, self.token_start_line)

        # Numbers
        if c.isdigit():
            return self.handle_number()

        # Strings
        if c == '"':
            return self.handle_string()

        # Operators
        ops = {
            '+': (TokenType.TOKEN_OP_PLUS, TokenType.TOKEN_OP_PLUS_ASSIGN, TokenType.TOKEN_OP_INCREMENT),
            '-': (TokenType.TOKEN_OP_MINUS, TokenType.TOKEN_OP_MINUS_ASSIGN, TokenType.TOKEN_OP_DECREMENT),
            '*': (TokenType.TOKEN_OP_MULTIPLY, TokenType.TOKEN_OP_MULTIPLY_ASSIGN, None),
            '/': (TokenType.TOKEN_OP_DIVIDE, TokenType.TOKEN_OP_DIVIDE_ASSIGN, None),
            '%': (TokenType.TOKEN_OP_MODULO, TokenType.TOKEN_OP_MOD_ASSIGN, None)
        }

        if c in ops:
            base, assign, special = ops[c]
            if self.match('='): return self.make_token(assign)
            if special and self.match(c): return self.make_token(special)
            if c == '/' and self.match('/'): return self.handle_comment()
            return self.make_token(base)

        # More operators
        if c == '=': return self.make_token(TokenType.TOKEN_OP_EQUAL if self.match('=') else TokenType.TOKEN_OP_ASSIGN)
        if c == '!': return self.make_token(TokenType.TOKEN_OP_NOT_EQUAL if self.match('=') else TokenType.TOKEN_OP_NOT)
        if c == '<': return self.make_token(TokenType.TOKEN_OP_LESS_EQUAL if self.match('=') else TokenType.TOKEN_OP_LESS)
        if c == '>': return self.make_token(TokenType.TOKEN_OP_GREATER_EQUAL if self.match('=') else TokenType.TOKEN_OP_GREATER)
        if c == '&': return self.make_token(TokenType.TOKEN_OP_AND) if self.match('&') else self.make_token(TokenType.TOKEN_OP_AND_ASSIGN) if self.match('=') else self.error_token("Unexpected '&'")
        if c == '|': return self.make_token(TokenType.TOKEN_OP_OR) if self.match('|') else self.make_token(TokenType.TOKEN_OP_OR_ASSIGN) if self.match('=') else self.error_token("Unexpected '|'")
        if c == '^': return self.make_token(TokenType.TOKEN_OP_XOR_ASSIGN) if self.match('=') else self.error_token("Unexpected '^'")

        # Delimiters
        delimiters = {
            ';': TokenType.TOKEN_DELIMITER_SEMICOLON,
            '(': TokenType.TOKEN_DELIMITER_LPAREN,
            ')': TokenType.TOKEN_DELIMITER_RPAREN,
            '{': TokenType.TOKEN_DELIMITER_LBRACE,
            '}': TokenType.TOKEN_DELIMITER_RBRACE,
            '[': TokenType.TOKEN_DELIMITER_LBRACKET,
            ']': TokenType.TOKEN_DELIMITER_RBRACKET,
            ',': TokenType.TOKEN_DELIMITER_COMMA
        }
        if c in delimiters:
            return self.make_token(delimiters[c])

        return self.error_token(f"Unexpected character '{c}'")

# ---------------------- GUI ---------------------- #
class ZLexerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Z-Language Lexer")
        self.geometry("1050x700")
        self.dark_mode = False
        apply_light_theme(self)
        self.tokens = []
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # ---------------- HEADER ---------------- #
        header = ttk.Frame(main_frame)
        header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header, text="Z-Language Lexer", font=("Segoe UI", 18, "bold")).pack(side=tk.LEFT)
        try:
            img = Image.open("z_logo.png").resize((70, 70))
            self.logo_img = ImageTk.PhotoImage(img)
            ttk.Label(header, image=self.logo_img).pack(side=tk.RIGHT)
        except:
            print("⚠ Logo not found. Include 'z_logo.png' in the same folder.")

        # ---------------- BUTTONS ---------------- #
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 5))
        ttk.Button(btn_frame, text="Load File", command=self.load_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Analyze", command=self.analyze).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Dark Mode", command=self.toggle_theme).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text="Clear", command=self.clear_all).pack(side=tk.RIGHT, padx=4)

        # ---------------- SPLIT SOURCE & TOKENS ---------------- #
        paned = tk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # --- Source Code Frame ---
        input_frame = ttk.Frame(paned)
        paned.add(input_frame, stretch="always")

        ttk.Label(input_frame, text="Source Code:").pack(anchor=tk.W)
        text_container = ttk.Frame(input_frame)
        text_container.pack(fill=tk.BOTH, expand=True)

        # Scrollbars
        y_scroll = ttk.Scrollbar(text_container)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll = ttk.Scrollbar(text_container, orient="horizontal")
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Line numbers
        self.line_numbers = tk.Text(
            text_container, width=5, padx=5, takefocus=0,
            border=0, background="#f0f0f0", state="disabled", wrap="none",
            font=("Consolas", 11)
        )
        self.line_numbers.pack(side=tk.LEFT, fill=tk.Y)

        # Main text input
        self.text_input = tk.Text(
            text_container, font=("Consolas", 11), wrap="none",
            yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set
        )
        self.text_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure scrollbars
        y_scroll.config(command=self._on_scroll)
        x_scroll.config(command=self.text_input.xview)
        self.text_input.bind("<KeyRelease>", lambda e: self.update_line_numbers())
        self.update_line_numbers()

        # --- Tokens Frame ---
        output_frame = ttk.Frame(paned)
        paned.add(output_frame, stretch="always")

        ttk.Label(output_frame, text="Tokens:").pack(anchor=tk.W)
        tree_container = ttk.Frame(output_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        tree_scroll = ttk.Scrollbar(tree_container)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            tree_container, columns=("Type", "Lexeme", "Line"), show="headings",
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.tree.yview)

        self.tree.heading("Type", text="Token Type")
        self.tree.heading("Lexeme", text="Lexeme")
        self.tree.heading("Line", text="Line")
        self.tree.column("Type", width=250, anchor=tk.W)
        self.tree.column("Lexeme", width=400, anchor=tk.W)
        self.tree.column("Line", width=80, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Pane sizing
        paned.paneconfig(input_frame, minsize=200)
        paned.paneconfig(output_frame, minsize=150)
        paned.sash_place(0, 0, 420)

    # ---------------- HELPER METHODS ---------------- #
    def _on_scroll(self, *args):
        """Sync vertical scrolling of text and line numbers."""
        self.text_input.yview(*args)
        self.line_numbers.yview(*args)

    def update_line_numbers(self):
        """Update the line numbers on the left."""
        self.line_numbers.config(state="normal")
        self.line_numbers.delete("1.0", tk.END)
        line_count = int(self.text_input.index('end-1c').split('.')[0])
        line_numbers_str = "\n".join(str(i) for i in range(1, line_count + 1))
        self.line_numbers.insert("1.0", line_numbers_str)
        self.line_numbers.config(state="disabled")

    # ---------------- BUTTON FUNCTIONS ---------------- #
    def toggle_theme(self):
        """Toggle between dark and light theme."""
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            apply_dark_theme(self)
        else:
            apply_light_theme(self)

    def load_file(self):
        """Load source code from a file."""
        filepath = filedialog.askopenfilename(
            title="Select Z-Language File",
            filetypes=[("Text Files", "*.txt"), ("Z Files", "*.z"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.text_input.delete("1.0", tk.END)
                self.text_input.insert("1.0", content)
                self.update_line_numbers()
                messagebox.showinfo("Success", f"Loaded: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{e}")

    def analyze(self):
        """Analyze source code and generate tokens."""
        source = self.text_input.get("1.0", tk.END)
        if not source.strip():
            messagebox.showwarning("Warning", "Please enter source code to analyze")
            return

        lexer = Lexer(source)
        self.tokens = []
        while True:
            token = lexer.scan_token()
            self.tokens.append(token)
            if token.type == TokenType.TOKEN_EOF:
                break

        self.display_tokens()
        messagebox.showinfo("Analysis Complete", f"Found {len(self.tokens)} tokens")

    def display_tokens(self):
        """Display tokens in the TreeView in order: Type → Lexeme → Line"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for token in self.tokens:
            type_str = TOKEN_TYPE_TO_STRING.get(token.type, "UNKNOWN")
            self.tree.insert("", tk.END, values=(type_str, token.lexeme, token.line))

    def export_csv(self):
        """Export tokens to CSV file."""
        if not self.tokens:
            messagebox.showwarning("Warning", "No tokens to export")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Token Type", "Lexeme", "Line"])
                    for token in self.tokens:
                        type_str = TOKEN_TYPE_TO_STRING.get(token.type, "UNKNOWN")
                        writer.writerow([type_str, token.lexeme, token.line])
                messagebox.showinfo("Success", f"Exported to: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export:\n{e}")

    def clear_all(self):
        """Clear the text editor and token display."""
        self.text_input.delete("1.0", tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tokens = []
        self.update_line_numbers()

# ---------------------- MAIN ---------------------- #
if __name__ == "__main__":
    app = ZLexerGUI()
    app.mainloop()
