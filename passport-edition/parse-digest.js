export function parse(str) {
	const hash = Uint8Array.from(str.replace(/\s/g, '').match(/../g).map(s => parseInt(s, 16)))

	return {
		salt: new Uint8Array(0),
		hash: hash,
	};
}