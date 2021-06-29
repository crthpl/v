// Copyright (c) 2019-2021 Alexander Medvednikov. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
module scanner

import os
import v.token
import v.pref
import v.errors
import v.util

pub struct Scanner {
pub mut:
	text                       string        // the file's text
	i                          int           // the current position in text
	col                        int           // the current column in text (0-based)
	line                       int           // the line number in text (0-based)
	file_path                  string        // the full path to the file
	file_base                  string        // the base path of the file (e.g. the base of `/home/john/abc.txt` is `abc.txt`)
	toks                       []token.Token // the list of tokens
	tokidx                     int // the current position in toks, used when parsing the tokens
	eofs                       int // the amount of times an eof token has been emited
	comments_mode              CommentsMode
	is_inside_toplvl_statement bool // set by the parser, to make sure that only top-level comments are parsed when using vdoc
	is_string_inter            bool
	is_string_inter_end        bool
	quote                      byte
	is_enclosed_inter          bool
	pref                       &pref.Preferences
	errors                     []errors.Error
	warnings                   []errors.Warning
}

/*
How the .toplevel_comments mode works:

In this mode, the scanner scans *everything* at once, before parsing starts,
including all the comments, and stores the results in an buffer s.all_tokens.

Then .scan() just returns s.all_tokens[ s.tidx++ ] *ignoring* the
comment tokens. In other words, by default in this mode, the parser
*will not see any comments* inside top level statements, so it has
no reason to complain about them.

When the parser determines, that it is outside of a top level statement,
it tells the scanner to backtrack s.tidx to the current p.tok index,
then it changes .is_inside_toplvl_statement to false , and refills its
lookahead buffer (i.e. p.peek_tok), from the scanner.

In effect, from the parser's point of view, the next tokens, that it will
receive with p.next(), will be the same, as if comments are not ignored
anymore, *between* top level statements.

When the parser determines, that it is going again inside a top level
statement, it does the same, this time setting .is_inside_toplvl_statement
to true, again refilling the lookahead buffer => calling .next() in this
mode, will again ignore all the comment tokens, till the top level statement
is finished.
*/
// The different kinds of scanner modes:
//
// .skip_comments - simplest/fastest, just ignores all comments early.
// This mode is used by the compiler itself.
//
// .parse_comments is used by vfmt. Ideally it should handle inline /* */
// comments too, i.e. it returns every kind of comment as a new token.
//
// .toplevel_comments is used by vdoc, parses *only* top level ones
// that are *outside* structs/enums/fns.
pub enum CommentsMode {
	skip_comments
	parse_comments
	toplevel_comments
}

// new scanner from file.
pub fn new_scanner_file(file_path string, comments_mode CommentsMode, pref &pref.Preferences) &Scanner {
	if !os.exists(file_path) {
		verror("$file_path doesn't exist")
	}
	$if debug_scanner ? {
		eprintln('file: $file_path')
	}
	raw_text := util.read_file(file_path) or {
		verror(err.msg)
		return voidptr(0)
	}
	mut s := &Scanner{
		pref: pref
		text: raw_text
		comments_mode: comments_mode
		file_path: file_path
		file_base: os.base(file_path)
	}
	s.init_scanner()
	return s
}

// new scanner from string.
pub fn new_scanner(text string, comments_mode CommentsMode, pref &pref.Preferences) &Scanner {
	mut s := &Scanner{
		pref: pref
		text: text
		comments_mode: comments_mode
		file_path: 'internal_memory'
		file_base: 'internal_memory'
	}
	s.init_scanner()
	return s
}

fn (mut s Scanner) init_scanner() {
	util.get_timers().measure_pause('PARSE')
	s.scan_all_tokens_in_buffer()
	util.get_timers().measure_resume('PARSE')
}

[unsafe]
pub fn (mut s Scanner) free() {
	unsafe {
		s.text.free()
	}
}

[inline]
fn (s Scanner) should_parse_comment() bool {
	return (s.comments_mode == .parse_comments)
		|| (s.comments_mode == .toplevel_comments && !s.is_inside_toplvl_statement)
}

// NB: this is called by v's parser
pub fn (mut s Scanner) set_is_inside_toplevel_statement(newstate bool) {
	s.is_inside_toplvl_statement = newstate
}

fn verror(s string) {
	util.verror('scanner error', s)
}

// [direct_array_access]
pub fn (mut s Scanner) scan() token.Token {
	for {
		cidx := s.tokidx
		s.tokidx++
		if cidx >= s.toks.len {
			return s.eof()
		}
		if s.toks[cidx].kind == .comment && !s.should_parse_comment() {
			continue
		}
		return s.toks[cidx]
	}
	return s.eof()
}

[inline]
pub fn (mut s Scanner) peek_token(n int) token.Token {
	idx := s.tokidx + n
	if idx >= s.toks.len {
		return s.eof()
	}
	return s.toks[idx]
}

pub fn (mut s Scanner) codegen(newtext string) {
	$if debug_codegen ? {
		eprintln('scanner.codegen:\n $newtext')
	}
	// codegen makes sense only during normal compilation
	// feeding code generated V code to vfmt or vdoc will
	// cause them to output/document ephemeral stuff.
	if s.comments_mode == .skip_comments {
		s.toks.delete_last() // remove .eof from end of .all_tokens
		s.text += newtext
		old_tokidx := s.tokidx
		s.tokidx = s.toks.len
		s.scan_all_tokens_in_buffer()
		s.tokidx = old_tokidx
	}
}

fn (mut s Scanner) eof() token.Token {
	s.eofs++
	if s.eofs > 50 {
		s.line--
		panic('the end of file `$s.file_path` has been reached 50 times already, the v parser is probably stuck.
This should not happen. Please report the bug here, and include the last 2-3 lines of your source code:
https://github.com/vlang/v/issues/new?labels=Bug&template=bug_report.md')
	}
	s.inc()
	return token.Token{
		kind: .eof
		lit: ''
		line_nr: s.line
		col: s.col
		pos: s.i
		len: 1
	}
}

[inline]
fn (mut s Scanner) inc() {
	if s.i < s.text.len {
		if s.text[s.i] == `\n` {
			s.col = 0
			s.line++
		}
	}
	s.i++
	s.col++
}

fn (mut s Scanner) error(msg string) {
	pos := token.Position{
		line_nr: s.line
		pos: s.i
		col: s.col
	}
	if s.pref.output_mode == .stdout {
		eprintln(util.formatted_error('error:', msg, s.file_path, pos))
		exit(1)
	} else {
		if s.pref.fatal_errors {
			exit(1)
		}
		s.errors << errors.Error{
			file_path: s.file_path
			pos: pos
			reporter: .scanner
			message: msg
		}
	}
}

pub fn (mut s Scanner) warn(msg string) {
	if s.pref.warns_are_errors {
		s.error(msg)
		return
	}
	pos := token.Position{
		line_nr: s.line
		pos: s.i
		col: s.col
	}
	if s.pref.output_mode == .stdout {
		eprintln(util.formatted_error('warning:', msg, s.file_path, pos))
	} else {
		s.warnings << errors.Warning{
			file_path: s.file_path
			pos: pos
			reporter: .scanner
			message: msg
		}
	}
}

struct Bool128 {
mut:
	x [128]bool
}

fn build_valid_first_char_in_op() Bool128 {
	mut res := Bool128{}
	for i in int(token.Kind._op_beg_) + 1 .. int(token.Kind._op_end_) {
		res.x[token.token_str[i][0]] = true
	}
	return res
}

fn build_longest_op() int {
	mut max_len := 0
	for i in int(token.Kind._op_beg_) + 1 .. int(token.Kind._op_end_) {
		len := token.token_str[i].len
		if len > max_len {
			max_len = len
		}
	}
	return max_len
}

fn build_ops() map[string]token.Kind {
	mut res := map[string]token.Kind{}
	for i in int(token.Kind._op_beg_) + 1 .. int(token.Kind._op_end_) {
		res[token.token_str[i]] = token.Kind(i)
	}
	return res
}

const (
	valid_first_char_in_op = build_valid_first_char_in_op()
	longest_op             = build_longest_op()
	ops                    = build_ops()
)

fn (mut s Scanner) scan_all_tokens_in_buffer() {
	mut toks := []token.Token{cap: 100}
	tok_loop: for {
		// Check for end of file
		if s.i >= s.text.len {
			toks << s.eof()
			break
		}

		if s.is_string_inter {
			c := s.text[s.i]
			if c <= `\'` || (c >= `*` && c <= `-`) || (c >= `:` && c <= `@`)
				|| c >= `|` || c in [`\``, `^`, `\\`, `/`] {
				s.is_string_inter = false
				s.is_string_inter_end = true
				toks << token.Token{
					kind: .string
					lit: ''
					line_nr: s.line
					col: s.col
					pos: s.i
					len: 1
				}
				s.inc()
				continue tok_loop
			}
		}

		// Skip whitespace
		for s.text[s.i] in [` `, `\t`, `\r`, `\n`] {
			s.inc()
			if s.i >= s.text.len {
				toks << s.eof()
				break tok_loop
			}
		}

		// Check for end of file
		if s.i >= s.text.len {
			toks << s.eof()
			break
		}

		c := s.text[s.i]
		if s.is_string_inter_end {
			s.is_string_inter_end = false
			goto parse_string
		}
		match c {
			`a`...`z`, `A`...`Z`, `_` {
				pos := s.i
				col := s.col
				s.inc()
				mut cur_char := s.text[s.i]
				for (cur_char >= `a` && cur_char <= `z`)
					|| (cur_char >= `A` && cur_char <= `Z`)
					|| (cur_char >= `0` && cur_char <= `9`) || cur_char == `_` {
					s.inc()
					if s.i >= s.text.len {
						break
					}
					cur_char = s.text[s.i]
				}

				lit := s.text[pos..s.i]
				if lit in token.keywords {
					toks << token.Token{
						kind: token.keywords[lit]
						line_nr: s.line
						col: col
						pos: pos
						len: lit.len
					}
					continue
				}
				toks << token.Token{
					kind: .name
					lit: lit
					line_nr: s.line
					col: col
					pos: pos
					len: lit.len
				}
			}
			`0`...`9` {
				pos := s.i
				col := s.col
				s.inc()
				if c == `0` && s.text[s.i] in [`b`, `o`, `x`] {
					s.inc()
				}
				if s.text[s.i - 1] == `_` {
					s.error('separator `_` is only valid between digits in a numeric literal')
				}
				mut cur_char := s.text[s.i]
				for (cur_char >= `0` && cur_char <= `9`)
					|| (cur_char >= `a` && cur_char <= `f`)
					|| (cur_char >= `A` && cur_char <= `F`) || cur_char == `_` {
					s.inc()
					if cur_char == `_` && s.text[s.i] == `_` {
						s.error('cannot use `_` consecutively')
					}
					if s.i >= s.text.len {
						break
					}
					cur_char = s.text[s.i]
				}
				if cur_char == `.` && if s.i + 1 >= s.text.len {
					true
				} else {
					s.text[s.i + 1] != `.`
				} {
					s.inc()
					if s.i < s.text.len {
						cur_char = s.text[s.i]
						for (cur_char >= `0` && cur_char <= `9`)
							|| (cur_char >= `a` && cur_char <= `f`)
							|| (cur_char >= `A` && cur_char <= `F`)
							|| cur_char == `_` {
							s.inc()
							if cur_char == `_` && s.text[s.i] == `_` {
								s.error('cannot use `_` consecutively')
							}
							if s.i >= s.text.len {
								break
							}
							cur_char = s.text[s.i]
						}
					}
				}
				toks << token.Token{
					kind: .number
					lit: s.text[pos..s.i]
					line_nr: s.line
					col: col
					pos: pos
					len: s.i - pos
				}
			}
			`\'`, `"` {
				// this makes it so that if this was called
				mut skip := true
				s.quote = c
				goto parse_string_beg

				parse_string:
				skip = false

				parse_string_beg:
				if s.is_string_inter {
					s.is_string_inter = false
					toks << token.Token{
						kind: .string
						lit: ''
						line_nr: s.line
						col: s.col
						pos: s.i
						len: 1
					}
					s.inc()
					continue tok_loop
				}
				pos := s.i
				col := s.col
				line := s.line
				if skip {
					s.inc()
				}
				println('a')
				for {
					mut is_not_escaped := s.text[s.i - 1] != `\\`

					if s.text[s.i - 2] == `\\` && !is_not_escaped {
						is_not_escaped = true
					}

					if is_not_escaped {
						println('c')
						if s.i >= s.text.len {
							s.i--
							break
						}
						not_escape := s.text[s.i]
						if not_escape == s.quote {
							break
						}
						println('f')
						if not_escape == `$` {
							s.is_string_inter = true
							println('d')
							toks << token.Token{
								kind: .string
								lit: s.text[pos..s.i]
								line_nr: line
								col: col
								pos: pos
								len: s.i - pos - 1
							}
							toks << token.Token{
								kind: .str_dollar
								line_nr: s.line
								col: s.col
								pos: s.i
								len: 1
							}
							s.inc()
							println('e')
							continue tok_loop
						}
						println('b')
					}
					s.inc()
				}
				println('g')
				s.inc()
				toks << token.Token{
					kind: .string
					lit: s.text[pos..s.i]
					line_nr: line
					col: col
					pos: pos
					len: s.i - pos
				}
				println('h')
			}
			`\`` {
				col := s.col
				line := s.line
				s.inc()
				if s.text[s.i] == `\\` {
					pos := s.i - 1
					s.inc()
					escape := s.text[s.i]
					if escape !in [`x`, `n`, `r`, `\\`, `f`, `v`, `t`, `e`, `"`, `\'`, `\``] {
						s.warn('unknown escape sequence: `\\${rune(escape)}`')
					}
					if escape == `\`` {
						s.inc()
					}
					for {
						if s.text[s.i] == `\`` {
							s.inc()
							break
						}
						s.inc()
					}
					toks << token.Token{
						kind: .chartoken
						lit: s.text[pos..s.i]
						line_nr: line
						col: col
						pos: pos
						len: s.i - pos
					}
					continue tok_loop
				}
				if s.text[s.i] > 127 {
					s.error('unicode emojis not supported yet')
				}
				s.inc()
				if s.text[s.i] != `\`` {
					s.error('invalid character literal (more than one character), use quotes (\' or ") for stringsand backticks (`) for characters')
				}
				s.inc()
				toks << token.Token{
					kind: .chartoken
					lit: s.text[s.i - 2..s.i]
					line_nr: line
					col: col
					pos: s.i - 3
					len: 3
				}
			}
			`#` {
				pos := s.i + 1
				col := s.col
				for s.text[s.i] != `\n` {
					s.inc()
				}
				s.inc()
				toks << token.Token{
					kind: .hash
					lit: s.text[pos..s.i - 1]
					line_nr: s.line - 1
					col: col
					pos: pos
					len: s.i - pos - 1
				}
			}
			`@` {
				pos := s.i
				col := s.col
				s.inc()
				for {
					if s.i >= s.text.len {
						break
					}
					cur_char := s.text[s.i]
					if (cur_char < `a` || cur_char > `z`) && (cur_char < `A` || cur_char > `Z`) {
						break
					}
					s.inc()
				}
				name := s.text[pos..s.i]
				if name in token.valid_at_tokens || (name[1] == `c` && name[2] == `c`) {
					toks << token.Token{
						kind: .at
						lit: name
						line_nr: s.line
						col: col
						pos: pos
						len: name.len + 1
					}
					continue tok_loop
				}
				if token.is_key(name[1..]) {
					toks << token.Token{
						kind: .name
						lit: name[1..]
						line_nr: s.line
						col: col + 1
						pos: pos + 1
						len: name.len
					}
					continue tok_loop
				}

				mut at_error_msg := '@ must be used before keywords or compile time variables (e.g. `@type string` or `@FN`)'
				// If name is all uppercase, the user is probably looking for a compile time variable ("at-token")
				if name.is_upper() {
					at_error_msg += '\nAvailable compile time variables:\n$token.valid_at_tokens'
				}
				s.error(at_error_msg)
			}
			else {
				for mut i in 0 .. scanner.longest_op {
					len := scanner.longest_op - i
					if s.i + len > s.text.len {
						continue
					}
					text := s.text[s.i..s.i + len]
					if len == 3 && text[0] == `&` && text[1] == `&` && text[2] != ` ` {
						toks << token.Token{
							kind: .amp
							line_nr: s.line
							col: s.col
							pos: s.i
							len: 1
						}
						toks << token.Token{
							kind: .amp
							line_nr: s.line
							col: s.col + 1
							pos: s.i + 1
							len: 1
						}

						s.inc()
						s.inc()
						continue tok_loop
					}

					if text == '//' {
						if s.should_parse_comment() {
							s.error('comment parsing not supported')
						}
						for {
							s.inc()
							if s.text[s.i] == `\n` {
								continue tok_loop
							}
						}
					}
					if text == '/*' {
						if s.should_parse_comment() {
							s.error('comment parsing not supported')
						}
						s.inc()
						for {
							s.inc()
							if s.text[s.i] == `*` && s.text[s.i + 1] == `/` {
								s.inc()
								s.inc()
								continue tok_loop
							}
						}
					}
					kind := scanner.ops[text] or { continue }

					if kind in [.not_in, .not_is] && s.text[s.i + 3] !in [` `, `\t`, `\n`, `\r`] {
						toks << token.Token{
							kind: .not
							line_nr: s.line
							col: s.col
							pos: s.i
							len: 1
						}
						s.inc()
						continue tok_loop
					}
					toks << token.Token{
						kind: kind
						line_nr: s.line
						col: s.col
						pos: s.i
						len: len - 1
					}
					for _ in 0 .. len {
						s.inc()
					}
					continue tok_loop
				}

				s.error('unknown char: ${rune(c).str()}') // TODO: get unicode characters correctly
			}
		}
	}
	s.toks << toks
}
