export function parse(str) {
	const parts = str.split('$');

	if (parts[0] !== 'sha256') {
		throw new Error(`Unknown digest type: ${parts[0]}`);
	}

	if (parts.length !== 3) {
		throw new Error(`sha256 digest type should consist of 3 $-separated parts`);
	}

	return {
		salt: Uint8Array.from(atob(parts[1]), s => s.charCodeAt(0)),
		hash: Uint8Array.from(atob(parts[2]), s => s.charCodeAt(0)),
	};
}