import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath, pathToFileURL} from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const dependencies = process.env.USDD_CONTRACT_DEPS ?? root;
const require = createRequire(path.join(dependencies, 'package.json'));
const solc = require('solc');
const {createHardhatRuntimeEnvironment} = await import(pathToFileURL(
  path.join(dependencies, 'node_modules/hardhat/dist/src/hre.js')));
const sources = {};
function add(file) {
  if (sources[file]) return;
  const content = fs.readFileSync(path.join(root, 'contracts-src', file), 'utf8');
  sources[file] = {content};
  for (const match of content.matchAll(/from "([^"]+)"/g)) {
    add(path.posix.normalize(path.posix.join(path.posix.dirname(file), match[1])));
  }
}
add('test/JoinedRedemptionV4Test.sol');
add('SP1AlphaRedemptionProofVerifierV3.sol');
const output = JSON.parse(solc.compile(JSON.stringify({language: 'Solidity', sources,
  settings: {optimizer: {enabled: true, runs: 200}, viaIR: true, evmVersion: 'cancun',
    outputSelection: {'*': {'*': ['evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.methodIdentifiers']}}}})));
assert.deepEqual((output.errors ?? []).filter(e => e.severity === 'error'), []);
const vault = output.contracts['USDDVaultV4.sol'].USDDVaultV4;
assert(vault.evm.deployedBytecode.object.length / 2 <= 24576);
const artifact = output.contracts['test/JoinedRedemptionV4Test.sol'].JoinedRedemptionV4Test;
const hre = await createHardhatRuntimeEnvironment({
  paths: {cache: path.join(root, 'cache'), artifacts: path.join(root, 'artifacts')},
  networks: {local: {type: 'edr-simulated', hardfork: 'cancun'}}}, {}, root);
const connection = await hre.network.create('local');
try {
  const rpc = (method, params = []) => connection.provider.request({method, params});
  const [from] = await rpc('eth_accounts');
  const tx = await rpc('eth_sendTransaction', [{from, data: '0x' + artifact.evm.bytecode.object, gas: '0x1c9c380'}]);
  const receipt = await rpc('eth_getTransactionReceipt', [tx]);
  assert.equal(receipt.status, '0x1');
  const result = await rpc('eth_call', [{from, to: receipt.contractAddress,
    data: '0x' + artifact.evm.methodIdentifiers['run()'], gas: '0x1c9c380'}, 'latest']);
  assert.equal(BigInt(result), 1n);
  console.log('PASS: V4 partial/full payout, liabilities, recipient and duplicate-burn checks; proof boundary mocked.');
} finally {
  await connection.close();
}
