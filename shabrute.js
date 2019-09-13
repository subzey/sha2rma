/**
 * Module level constant
 * Is a power of 8, to work nice with the reducer.
 * Is not too small, to fully utilize the WebGL prallelism.
 * Is not too big, to keep GPU buffers size under 10 Mb.
 */
const HASHES_COUNT = 8 ** 6;

/**
 * Entry function.
 * Works only if the total (salt length) + (password length) is <= 55 bytes.
 * (Which is actually very typical for salted password hashes)
 * @param { Uint8Array } salt Salt used when hashing.
 * @param { Uint8Array } hash Salted hash.
 * @param { number } pwdLen Password length
 * @returns { number | undefined }
 */
export function main(salt, hash, pwdLen) {
	/** Canvas or OffscreenCanvas, works either way */
	const a = /* new OffscreenCanvas(1, 1); */ document.createElement('canvas');

	/** WebGL2 context. WebGL v.1 won't do. */
	const gl = a.getContext('webgl2') || a.getContext('experimental-webgl2');

	// Shut down a part of the pipeline, so only vertex shader works
	gl.enable(gl.RASTERIZER_DISCARD);
	// Use (any) transform feedback.
	// Without the transform feedback all the output data from vertex shaders ("varyings")
	// is passed into fragment shaders and then simply thrown away.
	// Transform feedback is able to intercept these outputs from vertex shaders and store
	// it into a buffer.
	gl.bindTransformFeedback(gl.TRANSFORM_FEEDBACK, gl.createTransformFeedback());

	const bruteForceProgram = new BruteForceProgram(gl, salt, hash, pwdLen);
	const reducerProgram = new ReducerProgram(gl);

	// Probably we got some error at this stage.
	// WebGL doesn't throw, we have to throw manually.
	if (gl.getError() !== 0) {
		throw new Error(`WebGL Error ${gl.getError()}`);
	}

	// Each password char may be any ASCII value from 0x21 to 0x7E
	// That's 94 possible values. A password of length N can have 94**N values.
	// Split into batches of HASHES_COUNT and get the count of that batches.
	const iterationsCount = Math.ceil(Math.pow(94, pwdLen) / HASHES_COUNT);

	for (let iteration = 0; iteration < iterationsCount; iteration++) {
		const resultBuffer = bruteForceProgram.run(iteration);

		// Reading that buffer back into the JavaScriptLand would cost
		// a lot of time. Reducer program extracts and returns anything
		// that is not a -1. Or -1 if there's nothing except -1.
		const matchingId = reducerProgram.run(resultBuffer);
		if (matchingId !== -1) {
			console.log(`Found at iteration ${iteration}, id ${matchingId}`);
			return getPassword(iteration, matchingId, pwdLen);
		}
	}
}

/**
 * Gets two Uint32's and creates a password from these.
 * Something like Number::toString(base), but allows much bigger bases and
 * an ad-hoc BigInt support.
 * The implementation is exactly the same as void divmod() in the GLSL code.
 * This way we can plug in the same iterationId and vertexId and get
 * the same password as an output.
 * @param { number } divmod_hi Iteration id
 * @param { number } divmod_lo Vertex id
 * @param { number } len Password length
 * @returns { string }
 */
function getPassword(divmod_hi, divmod_lo, len) {
	if (len <= 0) {
		return '';
	}

	divmod_lo += divmod_hi % 94 * HASHES_COUNT;
	return (
		String.fromCharCode(divmod_lo % 94 + 33) +
		getPassword((divmod_hi / 94) >>> 0, (divmod_lo / 94) >>> 0, len - 1)
	);
}

/**
 * Read the Uint8Array as a *big endian* Uint32[].
 * SHA256 works only with big endian.
 * @param { Uint8Array } uia
 * @returns { Uint32Array }
 */
function asUint32BEArray(uia) {
	const ui32a = new Uint32Array(uia.byteLength / 4);
	const dataView = new DataView(uia.buffer, uia.byteOffset, uia.byteLength);

	for (let i = 0; i * 4 < uia.byteLength; i++) {
		ui32a[i] = dataView.getUint32(i * 4, false);
	}

	return ui32a;
}

/** Hard-coded initial values */
const sha256IV = Uint32Array.of(
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
)

/** A SHA256 computation/comparison GLSL program. */
class BruteForceProgram {
	/**
	 * @param { WebGL2RenderingContext } gl
	 * @param { Uint8Array } salt
	 * @param { Uint8Array } hash
	 * @param { number } pwdLen
	 */
	constructor(gl, salt, hash, pwdLen) {

		this._gl = gl;
		console.log(salt, hash);
		this._saltLen = salt.byteLength;
		this._pwdLen = pwdLen;

		// SHA256 expects blocks of length 64 (512 bits) as an input.
		// Typically there's several blocks, but in our specific case,
		// there's only one.
		const block = new Uint8Array(64);
		// Salt binary data is the start of the buffer.
		block.set(salt, 0);

		// then `_pwdLen` zero bytes

		// then, the padding
		block[salt.byteLength + this._pwdLen] = 0x80;

		// From on, we work with Uint32s.
		const hashU32 = asUint32BEArray(hash);

		const blockU32 = asUint32BEArray(block);
		// The last Uint32 is the message (salt + password) length.
		// It's in bits, not bytes, so multiply by 8.
		blockU32[15] = (salt.byteLength + this._pwdLen) * 8;

		// Our block is ready:
		// [ salt ] + [ pwdLen zero bytes ] [1 bit padding] [lots of zeroes] [ msg length ]
		console.log(Array.from(blockU32, v=>v.toString(16).padStart(8, 0)));

		// The actual password bytes will be substituted into [ pwdLen zero bytes ]
		// later when the GL program runs.

		const program = this._program = gl.createProgram();

		{
			// Just a debug variable
			let debugSource = '';
			const vShader = gl.createShader(gl.VERTEX_SHADER);
			gl.shaderSource(vShader, debugSource = `#version 300 es
/** Uniform input: iteration number */
uniform uint u_iteration;

/** Output: gl_VertexID if the hasing is okay, -1 otherwise */
flat out int v_matched_id;

/** BigInt base converter as described above */
void divmod(inout uvec2 state, out uint mod) {
	state[1] += state[0] % 94U * ${ HASHES_COUNT }U;
	mod = state[1] % 94U + 33U;
	state /= 94U;
}

/**
 * SHA256 round procedure.
 * These kind of functions in GLSL are actually procedures, so they change
 * values in-place instead of returning some value.
 */
void sha256round(
	const in uint wi,
	const in uint ki,
	const in uint a,
	const in uint b,
	const in uint c,
	inout uint d,
	const in uint e,
	const in uint f,
	const in uint g,
	inout uint h
) {
	// Mostly just a copy-paste from Wikipedia
	// As there's no ror() function in GLSL the expressions
	// like (e >> 6) ^ (e << 26) is used instead

	uint S1 = (e >> 6) ^ (e << 26) ^ (e >> 11) ^ (e << 21) ^ (e >> 25) ^ (e << 7);
	uint ch = (e & f) ^ (~e & g);
	uint temp1 = h + S1 + ch + ki + wi;
	uint S0 = (a >> 2) ^ (a << 30) ^ (a >> 13) ^ (a << 19) ^ (a >> 22) ^ (a << 10);
	uint maj = (a & b) ^ (a & c) ^ (b & c);
	uint temp2 = S0 + maj;

	d += temp1;
	h = temp1 + temp2;
}

/** Block expansion procedure */
void sha256expand(
	const in uint w2,
	const in uint w7,
	const in uint w15,
	const in uint w16,
	out uint w0
) {
	// Again, Wikipedia copy-paste

	uint s0 = (w15 >>  7) ^ (w15 << 25) ^ (w15 >> 18) ^ (w15 << 14) ^ (w15 >>  3);
	uint s1 = (w2  >> 17) ^ (w2  << 15) ^ (w2  >> 19) ^ (w2  << 13) ^ (w2  >> 10);
	w0 = w16 + s0 + w7 + s1;
}

/** Entry function */
void main() {
	// A default "return value" of the function
	v_matched_id = -1;

	/**
	 * A (16 + 48) * 32 bits block
	 * Some of the values are hard-coded from JS so we don't have to
	 * pass these as parameters over and over again.
	 * Zero values will be filled in the loop below.
	 */
	uint w[64] = uint[64](
		${blockU32[ 0]}U, ${blockU32[ 1]}U, ${blockU32[ 2]}U, ${blockU32[ 3]}U,
		${blockU32[ 4]}U, ${blockU32[ 5]}U, ${blockU32[ 6]}U, ${blockU32[ 7]}U,
		${blockU32[ 8]}U, ${blockU32[ 9]}U, ${blockU32[10]}U, ${blockU32[11]}U,
		${blockU32[12]}U, ${blockU32[13]}U, ${blockU32[14]}U, ${blockU32[15]}U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
		0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
	);

	// VertexID is a magic Int32 constant that is unique for each vertex.
	// 0 for vertex #0, 1 for vertex #1, etc. up to the HASHES_COUNT

	// Generate password bytes based on u_iteration, gl_VertexID
	// and plug them in the place they need to be.
	// We're working with Uint32s now, so we need some bit shifting

	uvec2 divmod_vec = uvec2(u_iteration, gl_VertexID);
	uint divmod_byte = 0U;

	// Let JS do its part and generate the GLSL code
	${ this._divmodCalls() }

	// Fill the zeroes
	for (int i = 16; i < 64; i++) {
		sha256expand(w[i-2], w[i-7], w[i-15], w[i-16], w[i]);
	}

	// Initial values
	// Typically these are carried over from the last call,
	// but we know there's only one block, so just hard-code it.
	uint a = ${ sha256IV[0] }U;
	uint b = ${ sha256IV[1] }U;
	uint c = ${ sha256IV[2] }U;
	uint d = ${ sha256IV[3] }U;
	uint e = ${ sha256IV[4] }U;
	uint f = ${ sha256IV[5] }U;
	uint g = ${ sha256IV[6] }U;
	uint h = ${ sha256IV[7] }U;

	// The unrolled loop.
	// It's just can use some GLSL magic and runs faster this way.
	sha256round(w[0 ], 0x428a2f98U, a, b, c, d, e, f, g, h);
	sha256round(w[1 ], 0x71374491U, h, a, b, c, d, e, f, g);
	sha256round(w[2 ], 0xb5c0fbcfU, g, h, a, b, c, d, e, f);
	sha256round(w[3 ], 0xe9b5dba5U, f, g, h, a, b, c, d, e);
	sha256round(w[4 ], 0x3956c25bU, e, f, g, h, a, b, c, d);
	sha256round(w[5 ], 0x59f111f1U, d, e, f, g, h, a, b, c);
	sha256round(w[6 ], 0x923f82a4U, c, d, e, f, g, h, a, b);
	sha256round(w[7 ], 0xab1c5ed5U, b, c, d, e, f, g, h, a);
	sha256round(w[8 ], 0xd807aa98U, a, b, c, d, e, f, g, h);
	sha256round(w[9 ], 0x12835b01U, h, a, b, c, d, e, f, g);
	sha256round(w[10], 0x243185beU, g, h, a, b, c, d, e, f);
	sha256round(w[11], 0x550c7dc3U, f, g, h, a, b, c, d, e);
	sha256round(w[12], 0x72be5d74U, e, f, g, h, a, b, c, d);
	sha256round(w[13], 0x80deb1feU, d, e, f, g, h, a, b, c);
	sha256round(w[14], 0x9bdc06a7U, c, d, e, f, g, h, a, b);
	sha256round(w[15], 0xc19bf174U, b, c, d, e, f, g, h, a);
	sha256round(w[16], 0xe49b69c1U, a, b, c, d, e, f, g, h);
	sha256round(w[17], 0xefbe4786U, h, a, b, c, d, e, f, g);
	sha256round(w[18], 0x0fc19dc6U, g, h, a, b, c, d, e, f);
	sha256round(w[19], 0x240ca1ccU, f, g, h, a, b, c, d, e);
	sha256round(w[20], 0x2de92c6fU, e, f, g, h, a, b, c, d);
	sha256round(w[21], 0x4a7484aaU, d, e, f, g, h, a, b, c);
	sha256round(w[22], 0x5cb0a9dcU, c, d, e, f, g, h, a, b);
	sha256round(w[23], 0x76f988daU, b, c, d, e, f, g, h, a);
	sha256round(w[24], 0x983e5152U, a, b, c, d, e, f, g, h);
	sha256round(w[25], 0xa831c66dU, h, a, b, c, d, e, f, g);
	sha256round(w[26], 0xb00327c8U, g, h, a, b, c, d, e, f);
	sha256round(w[27], 0xbf597fc7U, f, g, h, a, b, c, d, e);
	sha256round(w[28], 0xc6e00bf3U, e, f, g, h, a, b, c, d);
	sha256round(w[29], 0xd5a79147U, d, e, f, g, h, a, b, c);
	sha256round(w[30], 0x06ca6351U, c, d, e, f, g, h, a, b);
	sha256round(w[31], 0x14292967U, b, c, d, e, f, g, h, a);
	sha256round(w[32], 0x27b70a85U, a, b, c, d, e, f, g, h);
	sha256round(w[33], 0x2e1b2138U, h, a, b, c, d, e, f, g);
	sha256round(w[34], 0x4d2c6dfcU, g, h, a, b, c, d, e, f);
	sha256round(w[35], 0x53380d13U, f, g, h, a, b, c, d, e);
	sha256round(w[36], 0x650a7354U, e, f, g, h, a, b, c, d);
	sha256round(w[37], 0x766a0abbU, d, e, f, g, h, a, b, c);
	sha256round(w[38], 0x81c2c92eU, c, d, e, f, g, h, a, b);
	sha256round(w[39], 0x92722c85U, b, c, d, e, f, g, h, a);
	sha256round(w[40], 0xa2bfe8a1U, a, b, c, d, e, f, g, h);
	sha256round(w[41], 0xa81a664bU, h, a, b, c, d, e, f, g);
	sha256round(w[42], 0xc24b8b70U, g, h, a, b, c, d, e, f);
	sha256round(w[43], 0xc76c51a3U, f, g, h, a, b, c, d, e);
	sha256round(w[44], 0xd192e819U, e, f, g, h, a, b, c, d);
	sha256round(w[45], 0xd6990624U, d, e, f, g, h, a, b, c);
	sha256round(w[46], 0xf40e3585U, c, d, e, f, g, h, a, b);
	sha256round(w[47], 0x106aa070U, b, c, d, e, f, g, h, a);
	sha256round(w[48], 0x19a4c116U, a, b, c, d, e, f, g, h);
	sha256round(w[49], 0x1e376c08U, h, a, b, c, d, e, f, g);
	sha256round(w[50], 0x2748774cU, g, h, a, b, c, d, e, f);
	sha256round(w[51], 0x34b0bcb5U, f, g, h, a, b, c, d, e);
	sha256round(w[52], 0x391c0cb3U, e, f, g, h, a, b, c, d);
	sha256round(w[53], 0x4ed8aa4aU, d, e, f, g, h, a, b, c);
	sha256round(w[54], 0x5b9cca4fU, c, d, e, f, g, h, a, b);
	sha256round(w[55], 0x682e6ff3U, b, c, d, e, f, g, h, a);
	sha256round(w[56], 0x748f82eeU, a, b, c, d, e, f, g, h);
	sha256round(w[57], 0x78a5636fU, h, a, b, c, d, e, f, g);
	sha256round(w[58], 0x84c87814U, g, h, a, b, c, d, e, f);
	sha256round(w[59], 0x8cc70208U, f, g, h, a, b, c, d, e);

	// After this round the value of d and h won't change so we
	// can stop computing early.
	// If 2 out of 8 values doesn't match, the entire hash doesn't match.

	sha256round(w[60], 0x90befffaU, e, f, g, h, a, b, c, d);

	// Typically if statements in GLSL are discouraged, but in
	// this case there's a high chance the entire "wavefront" stops here.

	if( d != ${ hashU32[3] - sha256IV[3] }U || h != ${ hashU32[7] - sha256IV[7] }U) {
		return;
	}

	sha256round(w[61], 0xa4506cebU, d, e, f, g, h, a, b, c);
	if (c != ${ hashU32[2] - sha256IV[2] }U || g != ${ hashU32[6] - sha256IV[6] }U) {
		return;
	}

	sha256round(w[62], 0xbef9a3f7U, c, d, e, f, g, h, a, b);
	if (b != ${ hashU32[1] - sha256IV[1] }U || f != ${ hashU32[5] - sha256IV[5] }U) {
		return;
	}

	sha256round(w[63], 0xc67178f2U, b, c, d, e, f, g, h, a);
	if (a != ${ hashU32[0] - sha256IV[0] }U || e != ${ hashU32[4] - sha256IV[4] }U) {
		return;
	}

	// All checks passed: the block contains the guessed password
	// Return VertexID

	v_matched_id = gl_VertexID;
}
			`);
			console.log(debugSource);
			gl.compileShader(vShader);
			console.log('vShader', gl.getShaderInfoLog(vShader));
			gl.attachShader(program, vShader);
		}

		{
			// Create a fragment shader. It won't run anyway, so
			// it just needs to be something compile-able
			const fShader = gl.createShader(gl.FRAGMENT_SHADER);
			gl.shaderSource(fShader, `#version 300 es
				void main() {}
			`);
			gl.compileShader(fShader);
			console.log('fShader', gl.getShaderInfoLog(fShader));
			gl.attachShader(program, fShader);
		}

		// We wish to intercept a varying named v_matched_id
		gl.transformFeedbackVaryings(program, ['v_matched_id'], gl.INTERLEAVED_ATTRIBS);

		gl.linkProgram(program);
		console.log('program', gl.getProgramInfoLog(program));
		gl.validateProgram(program);
		console.log('program', gl.getProgramInfoLog(program));

		// Save the uniform location for later
		this._u_iteration = gl.getUniformLocation(program, 'u_iteration');

		// Create a buffer to fit HASHES_COUNT * 32 bits
		this._buffer = gl.createBuffer();
		// Set is as an active ARRAY_BUFFER
		gl.bindBuffer(gl.ARRAY_BUFFER, this._buffer);
		// Allocate HASHES_COUNT * 4 bytes
		gl.bufferData(gl.ARRAY_BUFFER, HASHES_COUNT * 4, gl.STATIC_DRAW);
	}

	_divmodCalls() {
		let rv = '';
		for (let i = 0; i < this._pwdLen; i++) {
			const intPtr = i + this._saltLen;
			const wordOffset = intPtr >>> 2;
			const bitShift = 24 - (intPtr % 4) * 8;

			rv += `
	divmod(divmod_vec, divmod_byte);
	w[${ wordOffset }] |= divmod_byte << ${ bitShift };
`;
		}

		return rv;
	}
	/**
	 * Run the program
	 * The result would be a buffer of (signed) Int32s.
	 * Each Int32 can be:
	 * - a nonnegative value: gl_VertexId that was used to generate
	 *   a hash and that hash it what we need.
	 * - -1 if the hashgenerated using gl_VertexId is not what we need.
	 * A typical output would be:
	 *     [..., -1, -1, -1, -1, -1, ...]
	 * If the "successful" VertexId was 42, it would be:
	 *     [..., -1, 42, -1, -1, -1, ...]
	 * @param { number } iteration Corrent iteration id
	 * @returns { WebGLBuffer }
	 */
	run(iteration) {
		const gl = this._gl;
		const program = this._program;
		// Set this program as a current program for drawArrays().
		gl.useProgram(program);
		// Pass the iteration id as a uniform value
		gl.uniform1ui(this._u_iteration, iteration);
		// Attach the "result" buffer
		gl.bindBufferBase(gl.TRANSFORM_FEEDBACK_BUFFER, 0, this._buffer);
		// Start the transform feedback
		gl.beginTransformFeedback(gl.POINTS);
		// Draw. Nothing will be "drawn" actually
		// It's just we start the vertex shader
		gl.drawArrays(gl.POINTS, 0, HASHES_COUNT);
		// Stop the transform feedback
		gl.endTransformFeedback();
		// Return this buffer
		return this._buffer;
	}
}

/** Gets the maximum value out of Int32 Buffer */
class ReducerProgram {
	constructor(gl) {
		this._gl = gl;

		const program = this._program = gl.createProgram();
		{
			let debugSource = '';
			const vShader = gl.createShader(gl.VERTEX_SHADER);

			// Read 8 int32 values (2 * ivec4) and returns the max value as v_max
			gl.shaderSource(vShader, debugSource = `#version 300 es
in ivec4 a_chunk0;
in ivec4 a_chunk1;
flat out int v_max;

void main() {
	ivec4 max_vec = max(a_chunk0, a_chunk1);
	v_max = max(
		max(max_vec[0], max_vec[1]),
		max(max_vec[2], max_vec[3])
	);
}

			`);
			console.log(debugSource);
			gl.compileShader(vShader);
			console.log('vShader', gl.getShaderInfoLog(vShader));
			gl.attachShader(program, vShader);
		}

		{
			// Create a fragment shader
			const fShader = gl.createShader(gl.FRAGMENT_SHADER);
			gl.shaderSource(fShader, `#version 300 es
				void main() {}
			`);
			gl.compileShader(fShader);
			console.log('fShader', gl.getShaderInfoLog(fShader));
			gl.attachShader(program, fShader);
		}

		// The max value `v_max` is written to the feedback buffer
		gl.transformFeedbackVaryings(program, ['v_max'], gl.INTERLEAVED_ATTRIBS);

		gl.linkProgram(program);
		console.log('program', gl.getProgramInfoLog(program));

		// Save the attributes locations for later
		this._a_chunk0 = gl.getAttribLocation(program, 'a_chunk0');
		this._a_chunk1 = gl.getAttribLocation(program, 'a_chunk1');

		// We will use an iternal temporary buffer
		this._tmp_buffer = gl.createBuffer();
		gl.bindBuffer(gl.ARRAY_BUFFER, this._tmp_buffer);
		// It byte-size is 8 times samller than the expected input buffer
		// Just enough to fit the return values on the first iteration
		gl.bufferData(gl.ARRAY_BUFFER, HASHES_COUNT / 2, gl.STATIC_DRAW);

		// Create the "read out" typed array once
		this._resultArray = new Int32Array(8);
	}

	/**
	 * After BruteForce program we have a huge buffer of values in the GPU memory.
	 * It can be just read back into the JavaScriptLand, but it would be damn slow.
	 * We can use GLSL to significantly reduce the size of that buffer right on the GPU side.
	 */
	run(inputBuffer) {
		const gl = this._gl;
		const program = this._program;

		gl.useProgram(program);

		// One of the buffers is the input, the other one is output
		let bufA = inputBuffer;
		let bufB = this._tmp_buffer;

		// Tell WebGL these attributes are not constant values and should be read from the input array
		gl.enableVertexAttribArray(this._a_chunk0);
		gl.enableVertexAttribArray(this._a_chunk1);

		let count = HASHES_COUNT
		for (; count > 8; count >>>= 3) {
			// BufA is the input array
			gl.bindBuffer(gl.ARRAY_BUFFER, bufA);

			// Tell where to find the Nth attribute in the buffer:
			// The a_chunk0 is a vec4 of int32 at offset `32 * N + 0`
			gl.vertexAttribIPointer(this._a_chunk0, 4, gl.INT, 32, 0);
			// The a_chunk1 is a vec4 of int32 at offset `32 * N + 16`
			gl.vertexAttribIPointer(this._a_chunk1, 4, gl.INT, 32, 16);
			// This way we pass 8 int32 values at once to the shader program instance

			// BufB is the output array
			gl.bindBufferBase(gl.TRANSFORM_FEEDBACK_BUFFER, 0, bufB);
			gl.beginTransformFeedback(gl.POINTS);

			// Draw (count / 8) chunks of 8 values each.
			gl.drawArrays(gl.POINTS, 0, count >>> 3);

			gl.endTransformFeedback();

			// Swap two buffers and repeat. We reuse the input array as an output array.
			// This would destroy the contents of the input buffer, but we don't need it anyway.
			[bufA, bufB] = [bufB, bufA];

			// This way, after each iteration bufA will countain 8 times less values:
			// 8 ** 6 -> 8 ** 5
			// 8 ** 5 -> 8 ** 4
			// And so on until we have 8 or less values
		}

		// Now we have <= 8 values in the buffer that is currently bound as a TRANSFORM_FEEDBACK_BUFFER
		// We could run the "reducing procedure" once again, but that would be just a waste of time:
		// Only one instance of shader program would run, and there's no parallelism.
		// It is faster to just read 8 values back.

		// Quick check the length of a typed array is correct
		if (this._resultArray.length !== count) {
			this._resultArray = new Int32Array(count);
		}

		// Read data back to the JavaScriptLand
		gl.getBufferSubData(gl.TRANSFORM_FEEDBACK_BUFFER, 0, this._resultArray, 0, count);

		// Cleanup:
		// If the inputArray still has bound attribute pointers, it cannot be used in the
		// BruteForce program again. We don't want that to happen!
		gl.bindBuffer(gl.ARRAY_BUFFER, this._tmp_buffer);
		gl.vertexAttribIPointer(this._a_chunk0, 4, gl.INT, 32, 0);
		gl.vertexAttribIPointer(this._a_chunk1, 4, gl.INT, 32, 16);
		gl.disableVertexAttribArray(this._a_chunk0);
		gl.disableVertexAttribArray(this._a_chunk1);

		// Return the overall max value
		return Math.max(...this._resultArray);
	}
}