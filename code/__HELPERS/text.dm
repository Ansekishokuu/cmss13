/*
 * Holds procs designed to help with filtering text
 * Contains groups:
 * SQL sanitization
 * Text sanitization
 * Text searches
 * Text modification
 * Misc
 */


/*
 * Text sanitization
 */

//Simply removes < and > and limits the length of the message
/proc/strip_html_simple(t, limit=MAX_MESSAGE_LEN)
	var/list/strip_chars = list("<",">")
	t = copytext(t,1,limit)
	for(var/char in strip_chars)
		var/index = findtext(t, char)
		while(index)
			t = copytext(t, 1, index) + copytext(t, index+1)
			index = findtext(t, char)
	return t

//Removes a few problematic characters
/proc/sanitize_simple(t,list/repl_chars = list("\n"="#","\t"="#"))
	for(var/char in repl_chars)
		var/index = findtext(t, char)
		while(index)
			t = copytext(t, 1, index) + repl_chars[char] + copytext(t, index + length(char))
			index = findtext(t, char, index + length(char))
		return t

///Helper for only alphanumeric characters plus common punctuation, spaces, underscore and hyphen _ -.
/proc/replace_non_alphanumeric_plus(text)
	var/regex/alphanumeric = regex(@{"[^a-z0-9 ,.?!\-_&]"}, "gi")
	return alphanumeric.Replace(text, "")

/proc/readd_quotes(text)
	var/list/repl_chars = list("&#34;" = "\"", "&#39;" = "'")
	for(var/char in repl_chars)
		text = replacetext(text, char, repl_chars[char])
	return text

//Runs byond's sanitization proc along-side sanitize_simple
/proc/sanitize(input, list/repl_chars = list("\n"=" ","\t"=" ","�"=" "))
	var/output = html_encode(sanitize_simple(input, repl_chars))
	return readd_quotes(output)

//Runs byond's sanitization proc along-side strip_improper
/proc/sanitize_area(input)
	var/output = html_encode(strip_improper(input))
	return readd_quotes(output)

//Removes control chars like "\n"
/proc/sanitize_control_chars(text)
	var/static/regex/whitelistedWords = regex(@{"([^\u0020-\u8000]+)"}, "g")
	return whitelistedWords.Replace(text, "")

//Runs sanitize and strip_html_simple
//I believe strip_html_simple() is required to run first to prevent '<' from displaying as '&lt;' after sanitize() calls byond's html_encode()
/proc/strip_html(text, limit=MAX_MESSAGE_LEN)
	return copytext((sanitize(strip_html_simple(text, limit))), 1, limit)

//Runs byond's sanitization proc along-side strip_html_simple
//I believe strip_html_simple() is required to run first to prevent '<' from displaying as '&lt;' that html_encode() would cause
/proc/adminscrub(text, limit=MAX_MESSAGE_LEN)
	return copytext((html_encode(strip_html_simple(text))), 1, limit)

//Returns null if there is any bad text in the string
/proc/reject_bad_text(text, max_length = 512, ascii_only = TRUE)
	var/char_count = 0
	var/non_whitespace = FALSE
	var/lenbytes = length(text)
	var/char = ""
	for(var/i = 1, i <= lenbytes, i += length(char))
		char = text[i]
		char_count++
		if(char_count > max_length)
			return
		switch(text2ascii(char))
			if(62, 60, 92, 47) // <, >, \, /
				return
			if(0 to 31)
				return
			if(32)
				continue
			if(127 to INFINITY)
				if(ascii_only)
					return
			else
				non_whitespace = TRUE
	if(non_whitespace)
		return text //only accepts the text if it has some non-spaces

// Used to get a properly sanitized input, of max_length
// no_trim is self explanatory but it prevents the input from being trimed if you intend to parse newlines or whitespace.
/proc/stripped_input(mob/user, message = "", title = "", default = "", max_length=MAX_MESSAGE_LEN, no_trim=FALSE)
	var/name = input(user, message, title, default) as text|null
	if(no_trim)
		return copytext(html_encode(name), 1, max_length)
	else
		return trim(html_encode(name), max_length) //trim is "outside" because html_encode can expand single symbols into multiple symbols (such as turning < into &lt;)
// Used to get a properly sanitized multiline input, of max_length
/proc/stripped_multiline_input(mob/user, message = "", title = "", default = "", max_length=MAX_MESSAGE_LEN, no_trim=FALSE)
	var/name = input(user, message, title, default) as message|null
	if(no_trim)
		return copytext(html_encode(name), 1, max_length)
	else
		return trim(html_encode(name), max_length)

#define NO_CHARS_DETECTED 0
#define SPACES_DETECTED 1
#define SYMBOLS_DETECTED 2
#define NUMBERS_DETECTED 3
#define LETTERS_DETECTED 4

//Filters out undesirable characters from names
/proc/reject_bad_name(t_in, allow_numbers = FALSE, max_length = MAX_NAME_LEN, ascii_only = TRUE)
	if(!t_in)
		return //Rejects the input if it is null

	var/number_of_alphanumeric = 0
	var/last_char_group = NO_CHARS_DETECTED
	var/t_out = ""
	var/t_len = length(t_in)
	var/charcount = 0
	var/char = ""


	for(var/i = 1, i <= t_len, i += length(char))
		char = t_in[i]

		switch(text2ascii(char))
			// A  .. Z
			if(65 to 90)			//Uppercase Letters
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			// a  .. z
			if(97 to 122)			//Lowercase Letters
				if(last_char_group == NO_CHARS_DETECTED || last_char_group == SPACES_DETECTED || last_char_group == SYMBOLS_DETECTED) //start of a word
					char = uppertext(char)
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			// 0  .. 9
			if(48 to 57)			//Numbers
				if(last_char_group == NO_CHARS_DETECTED || !allow_numbers) //suppress at start of string
					continue
				number_of_alphanumeric++
				last_char_group = NUMBERS_DETECTED

			// '  -  .
			if(39,45,46)			//Common name punctuation
				if(last_char_group == NO_CHARS_DETECTED)
					continue
				last_char_group = SYMBOLS_DETECTED

			// ~   |   @  :  #  $  %  &  *  +
			if(126,124,64,58,35,36,37,38,42,43)			//Other symbols that we'll allow (mainly for AI)
				if(last_char_group == NO_CHARS_DETECTED || !allow_numbers) //suppress at start of string
					continue
				last_char_group = SYMBOLS_DETECTED

			//Space
			if(32)
				if(last_char_group == NO_CHARS_DETECTED || last_char_group == SPACES_DETECTED) //suppress double-spaces and spaces at start of string
					continue
				last_char_group = SPACES_DETECTED

			if(127 to INFINITY)
				if(ascii_only)
					continue
				last_char_group = SYMBOLS_DETECTED //for now, we'll treat all non-ascii characters like symbols even though most are letters

			else
				continue

		t_out += char
		charcount++
		if(charcount >= max_length)
			break

	if(number_of_alphanumeric < 2)
		return		//protects against tiny names like "A" and also names like "' ' ' ' ' ' ' '"

	if(last_char_group == SPACES_DETECTED)
		t_out = copytext_char(t_out, 1, -1) //removes the last character (in this case a space)

	for(var/bad_name in list("space","floor","wall","r-wall","monkey","unknown","inactive ai"))	//prevents these common metagamey names
		if(cmptext(t_out,bad_name))
			return	//(not case sensitive)

	return t_out

#undef NO_CHARS_DETECTED
#undef SPACES_DETECTED
#undef NUMBERS_DETECTED
#undef LETTERS_DETECTED

//html_encode helper proc that returns the smallest non null of two numbers
//or 0 if they're both null (needed because of findtext returning 0 when a value is not present)
/proc/non_zero_min(a, b)
	if(!a)
		return b
	if(!b)
		return a
	return (a < b ? a : b)

/*
 * Text searches
 */

//Adds 'char' ahead of 'text' until there are 'count' characters total
/proc/add_leading(text, count, char = " ")
	var/charcount = count - length_char(text)
	var/list/chars_to_add[max(charcount + 1, 0)]
	return jointext(chars_to_add, char) + text

//Adds 'char' behind 'text' until there are 'count' characters total
/proc/add_trailing(text, count, char = " ")
	var/charcount = count - length_char(text)
	var/list/chars_to_add[max(charcount + 1, 0)]
	return text + jointext(chars_to_add, char)

//Returns a string with reserved characters and spaces before the first letter removed
/proc/trim_left(text)
	for (var/i = 1 to length(text))
		if (text2ascii(text, i) > 32)
			return copytext(text, i)
	return ""

//Returns a string with reserved characters and spaces after the last letter removed
/proc/trim_right(text)
	for (var/i = length(text), i > 0, i--)
		if (text2ascii(text, i) > 32)
			return copytext(text, 1, i + 1)
	return ""

//Returns a string with reserved characters and spaces after the first and last letters removed
//Like trim(), but very slightly faster. worth it for niche usecases
/proc/trim_reduced(text)
	var/starting_coord = 1
	var/text_len = length(text)
	for (var/i in 1 to text_len)
		if (text2ascii(text, i) > 32)
			starting_coord = i
			break

	for (var/i = text_len, i >= starting_coord, i--)
		if (text2ascii(text, i) > 32)
			return copytext(text, starting_coord, i + 1)

	if(starting_coord > 1)
		return copytext(text, starting_coord)
	return ""

/proc/pad_trailing(text, padding, size)
	while (length(text) < size)
		text = "[text][padding]"
	return text

/// Finds the first letter of each word in the provided string and capitalize them
/proc/capitalize_first_letters(string)
	var/list/text = splittext_char(string, " ")
	var/list/finalized_text = list()
	for(var/word in text)
		finalized_text += capitalize(word)
	return jointext(finalized_text, " ")

//Returns a string with reserved characters and spaces before the first word and after the last word removed.
/proc/trim(text, max_length)
	if(max_length)
		text = copytext_char(text, 1, max_length)
	return trim_left(trim_right(text))

//Returns a string with the first element of the string capitalized.
/proc/capitalize(t as text)
	. = t[1]
	return uppertext(.) + copytext(t, 1 + length(.))

/proc/stringmerge(text,compare,replace = "*")
//This proc fills in all spaces with the "replace" var (* by default) with whatever
//is in the other string at the same spot (assuming it is not a replace char).
//This is used for fingerprints
	var/newtext = text
	var/text_it = 1 //iterators
	var/comp_it = 1
	var/newtext_it = 1
	var/text_length = length(text)
	var/comp_length = length(compare)
	while(comp_it <= comp_length && text_it <= text_length)
		var/a = text[text_it]
		var/b = compare[comp_it]
//if it isn't both the same letter, or if they are both the replacement character
//(no way to know what it was supposed to be)
		if(a != b)
			if(a == replace) //if A is the replacement char
				newtext = copytext(newtext, 1, newtext_it) + b + copytext(newtext, newtext_it + length(newtext[newtext_it]))
			else if(b == replace) //if B is the replacement char
				newtext = copytext(newtext, 1, newtext_it) + a + copytext(newtext, newtext_it + length(newtext[newtext_it]))
			else //The lists disagree, Uh-oh!
				return 0
		text_it += length(a)
		comp_it += length(b)
		newtext_it += length(newtext[newtext_it])

	return newtext

/proc/stringpercent(text,character = "*")
//This proc returns the number of chars of the string that is the character
//This is used for detective work to determine fingerprint completion.
	if(!text || !character)
		return 0
	var/count = 0
	for(var/i = 1, i <= length(text), i++)
		var/a = copytext(text,i,i+1)
		if(a == character)
			count++
	return count

/proc/reverse_text(text = "")
	var/new_text = ""
	for(var/i = length(text); i > 0; i--)
		new_text += copytext(text, i, i+1)
	return new_text

GLOBAL_LIST_INIT(zero_character_only, list("0"))
GLOBAL_LIST_INIT(hex_characters, list("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"))
GLOBAL_LIST_INIT(alphabet, list("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"))
GLOBAL_LIST_INIT(binary, list("0","1"))

//Used in preferences' SetFlavorText and human's set_flavor verb
//Previews a string of len or less length
/proc/TextPreview(string, len=40)
	var/string_length = length(string)
	if(!string_length)
		return "\[...\]"
	else if(string_length <= len)
		return string
	else
		return "[copytext(string, 1, len - 3)]..."

/proc/strip_improper(input_text)
	return replacetext(replacetext(input_text, "\proper", ""), "\improper", "")

// Used to remove the string shortcuts for a clean transfer
/proc/sanitize_filename(t)
	return sanitize_simple(t, list("\n"="", "\t"="", "/"="", "\\"="", "?"="", "%"="", "*"="", ":"="", "|"="", "\""="", "<"="", ">"=""))

/proc/deep_string_equals(A, B)
	if(length(A) != length(B))
		return FALSE
	for(var/i = 1 to length(A))
		if (text2ascii(A, i) != text2ascii(B, i))
			return FALSE
	return TRUE

//Used for applying byonds text macros to strings that are loaded at runtime
/proc/apply_text_macros(string)
	var/next_backslash = findtext(string, "\\")
	if(!next_backslash)
		return string

	var/leng = length(string)

	var/next_space = findtext(string, " ", next_backslash + 1)
	if(!next_space)
		next_space = leng - next_backslash

	if(!next_space) //trailing bs
		return string

	var/base = next_backslash == 1 ? "" : copytext(string, 1, next_backslash)
	var/macro = lowertext(copytext(string, next_backslash + 1, next_space))
	var/rest = next_backslash > leng ? "" : copytext(string, next_space + 1)

	//See http://www.byond.com/docs/ref/info.html#/DM/text/macros
	switch(macro)
		//prefixes/agnostic
		if("the")
			rest = text("\the []", rest)
		if("a")
			rest = text("\a []", rest)
		if("an")
			rest = text("\an []", rest)
		if("proper")
			rest = text("\proper []", rest)
		if("improper")
			rest = text("\improper []", rest)
		if("roman")
			rest = text("\roman []", rest)
		//postfixes
		if("th")
			base = text("[]\th", rest)
		if("s")
			base = text("[]\s", rest)
		if("he")
			base = text("[]\he", rest)
		if("she")
			base = text("[]\she", rest)
		if("his")
			base = text("[]\his", rest)
		if("himself")
			base = text("[]\himself", rest)
		if("herself")
			base = text("[]\herself", rest)
		if("hers")
			base = text("[]\hers", rest)

	. = base
	if(rest)
		. += .(rest)
// Returns the location of the atom as a string in the following format:
// "Area Name (X, Y, Z)"
// Mainly used for logging
/proc/get_location_in_text(atom/A, include_jmp_link = TRUE)
	var/message
	if(!A.loc)
		message = "Invalid location"
	else
		if(include_jmp_link)
			message = "<a href='byond://?_src_=admin_holder;[HrefToken(forceGlobal = TRUE)];adminplayerobservecoodjump=1;X=[A.x];Y=[A.y];Z=[A.z]'>[get_area(A)]</a> ([A.x], [A.y], [A.z])"
		else
			message = "[get_area(A)] ([A.x], [A.y], [A.z])"
	return message

// Aurorastation Markup System
// For processing simple markup, similar to what Skype and Discord use.
// Enabled from a config setting.
/proc/process_chat_markup(message, list/ignore_tags = list())
	if (!message)
		return ""

	// ---Begin URL caching.
	var/list/urls = list()
	var/i = 1
	while (GLOB.url_find_lazy.Find_char(message))
		urls["\ref[urls]-[i]"] = GLOB.url_find_lazy.match
		i++

	for (var/ref in urls)
		message = replacetextEx_char(message, urls[ref], ref)
	// ---End URL caching

	var/regex/tag_markup
	for (var/tag in (GLOB.markup_tags - ignore_tags))
		tag_markup = GLOB.markup_regex[tag]
		message = tag_markup.Replace_char(message, "$2[GLOB.markup_tags[tag][1]]$3[GLOB.markup_tags[tag][2]]$5")

	// ---Unload URL cache
	for (var/ref in urls)
		message = replacetextEx_char(message, ref, urls[ref])

	return message

#define SMALL_FONTS(FONTSIZE, MSG) "<span style=\"font-family: 'Small Fonts'; -dm-text-outline: 1 black; font-size: [FONTSIZE]px;\">[MSG]</span>"
#define SMALL_FONTS_CENTRED(FONTSIZE, MSG) "<center><span style=\"font-family: 'Small Fonts'; -dm-text-outline: 1 black; font-size: [FONTSIZE]px;\">[MSG]</span></center>"
#define SMALL_FONTS_COLOR(FONTSIZE, MSG, COLOR) "<span style=\"font-family: 'Small Fonts'; -dm-text-outline: 1 black; font-size: [FONTSIZE]px; color: [COLOR];\">[MSG]</span>"

//finds the first occurrence of one of the characters from needles argument inside haystack
//it may appear this can be optimised, but it really can't. findtext() is so much faster than anything you can do in byondcode.
//stupid byond :(
/proc/findchar(haystack, needles, start=1, end=0)
	var/char = ""
	var/len = length(needles)
	for(var/i = 1, i <= len, i += length(char))
		char = needles[i]
		. = findtextEx(haystack, char, start, end)
		if(.)
			return
	return 0

/// Check if the string `haystack` begins with the string `needle`.
/proc/string_starts_with(haystack, needle)
	return (copytext(haystack, 1, length(needle) + 1) == needle)


/proc/text2charlist(text)
	var/char = ""
	var/lentext = length(text)
	. = list()
	for(var/i = 1, i <= lentext, i += length(char))
		char = text[i]
		. += char

/proc/rot13(text = "")
	var/lentext = length(text)
	var/char = ""
	var/ascii = 0
	. = ""
	for(var/i = 1, i <= lentext, i += length(char))
		char = text[i]
		ascii = text2ascii(char)
		switch(ascii)
			if(65 to 77, 97 to 109) //A to M, a to m
				ascii += 13
			if(78 to 90, 110 to 122) //N to Z, n to z
				ascii -= 13
		. += ascii2text(ascii)
