(function() {
  if (!window.crypto) {
    throw new Error('crypto object not available');
  }

  var crypto = window.crypto, array = new Uint32Array(1);

  // higher carry bits get consumed first, carry_bits guaranteed to be < 32
  var carry = 0, carry_bits = 0;

  var log2 = Math.log2 || function(x) {
    return Math.log(x) / Math.LN2;
  }, max_max = 0xffffffff;

  /**
   * rejection sampling routine for crypto.getRandomValues()
   *
   * note: take care when using bitwise operations on the return value - if max
   * is greater than 2^31-1, the bitwise operations have a good chance of
   * turning the value into a signed integer
   *
   * @param {number} max must be an integer in [0,2^32)
   * @return {number} a random value between the specified integers
   */
  function reject(max) {
    if (typeof max !== 'number') {
      throw new TypeError('max is not a number');
    }

    if (!(max > 0) || max !== Math.floor(max) || max > max_max) {
      throw new RangeError('max must be an integer > 0');
    }

    var log = log2(max + 1), flog = log | 0, bits = flog + (log !== flog);

    var val;

    // this branch is technically taken for just over half of the possible max
    // values, despite the fact that the distribution of max values is totally
    // unknown
    if (bits === 32) {
      for (;;) {
        crypto.getRandomValues(array);
        if ((val = array[0]) <= max) {
          return val;
        }
      }
    }

    for (;;) {
      // use as much from the carry pool as we can, take the rest from a crypto
      // call
      var from_carry = Math.min(carry_bits, bits),
        from_crypto = bits - from_carry;

      // bits left after we take what we need (will be 0 if from_crypto)
      carry_bits -= from_carry;
      // take higher bits first, throw at the bottom of val
      // also mask out already used carry bits
      val = (carry >>> carry_bits) & ((1 << bits) - 1);

      if (from_crypto) {
        crypto.getRandomValues(array);
        carry = array[0];
        // bits left after we take what we need
        carry_bits = 32 - from_crypto;
        // take the higher bits first, shove it at the top of val
        val |= (carry >>> carry_bits) << from_carry;
      }

      if (val <= max) {
        return val;
      }
    }
  }

  reject.old_crypto_reject = window.crypto_reject;
  window.crypto_reject = reject;
})();
