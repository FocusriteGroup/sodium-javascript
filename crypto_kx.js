/* eslint-disable camelcase */
const { crypto_scalarmult_BYTES, crypto_scalarmult_base, crypto_scalarmult } = require('./crypto_scalarmult')
const { crypto_generichash } = require('./crypto_generichash')
const { randombytes_buf } = require('./randombytes')
const { sodium_memzero } = require('./memory')
const assert = require('nanoassert')

const crypto_kx_SEEDBYTES = 32
const crypto_kx_PUBLICKEYBYTES = 32
const crypto_kx_SECRETKEYBYTES = 32
const crypto_kx_SESSIONKEYBYTES = 32;

function crypto_kx_keypair (pk, sk) {
  assert(pk.byteLength === crypto_kx_PUBLICKEYBYTES, "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes")
  assert(sk.byteLength === crypto_kx_SECRETKEYBYTES, "sk must be 'crypto_kx_SECRETKEYBYTES' bytes")

  randombytes_buf(sk, crypto_kx_SECRETKEYBYTES)
  return crypto_scalarmult_base(pk, sk)
}

function crypto_kx_seed_keypair (pk, sk, seed) {
  assert(pk.byteLength === crypto_kx_PUBLICKEYBYTES, "pk must be 'crypto_kx_PUBLICKEYBYTES' bytes")
  assert(sk.byteLength === crypto_kx_SECRETKEYBYTES, "sk must be 'crypto_kx_SECRETKEYBYTES' bytes")
  assert(seed.byteLength === crypto_kx_SEEDBYTES, "seed must be 'crypto_kx_SEEDBYTES' bytes")

  crypto_generichash(sk, seed)
  return crypto_scalarmult_base(pk, sk)
}

function crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) {
  assert(client_pk.byteLength === crypto_kx_PUBLICKEYBYTES, "client_pk must be 'crypto_kx_PUBLICKEYBYTES' bytes");
  assert(client_sk.byteLength === crypto_kx_SECRETKEYBYTES, "client_sk must be 'crypto_kx_SECRETKEYBYTES' bytes");
  assert(server_pk.byteLength === crypto_kx_PUBLICKEYBYTES, "server_pk must be 'crypto_kx_PUBLICKEYBYTES' bytes");

  if (!rx){
    rx = tx;
  }

  if (!tx){
    tx = rx;
  }

  if (!rx){
    throw new Error('requires session key bytes');
  }

  const q = new Uint8Array(crypto_scalarmult_BYTES);
  if (crypto_scalarmult(q, client_sk, server_pk) !== 0) {
    throw new Error('crypto_scalarmult failed');
  }

  const keys = new Uint8Array(2 * crypto_kx_SESSIONKEYBYTES);
  const hashInput = new Uint8Array(q.length + client_pk.length + server_pk.length);
  hashInput.set(q, 0);
  hashInput.set(client_pk, q.length);
  hashInput.set(server_pk, q.length + client_pk.length);

  crypto_generichash(keys, hashInput);

  for (let i = 0; i < crypto_kx_SESSIONKEYBYTES; i++) {
    rx[i] = keys[i];
    tx[i] = keys[i + crypto_kx_SESSIONKEYBYTES];
  }

  sodium_memzero(q);
  sodium_memzero(keys);

  return 0;
}

module.exports = {
  crypto_kx_keypair,
  crypto_kx_seed_keypair,
  crypto_kx_client_session_keys,
  crypto_kx_SEEDBYTES,
  crypto_kx_SECRETKEYBYTES,
  crypto_kx_PUBLICKEYBYTES
}
