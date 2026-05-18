import fs from "node:fs"

import { Connection, Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL, TransactionMessage, VersionedTransaction } from "@solana/web3.js"
import * as multisig from "@sqds/multisig"

const PROGRAM_ID = new PublicKey("SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")

async function main() {
    const connection = new Connection("https://api.mainnet-beta.solana.com")

    const creator   = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync("creator-keypair.json", "utf-8"))))
    const createKey = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync("createkey-keypair.json", "utf-8"))))

    const [multisigPda] = multisig.getMultisigPda({ createKey: createKey.publicKey, programId: PROGRAM_ID })
    const [vaultPda] = multisig.getVaultPda({ multisigPda, index: 0, programId: PROGRAM_ID })
    const [programConfigPda] = multisig.getProgramConfigPda({ programId: PROGRAM_ID })

    const programConfig = await multisig.accounts.ProgramConfig.fromAccountAddress(connection, programConfigPda)
    const treasury = programConfig.treasury

    const createIx = multisig.instructions.multisigCreateV2({
        treasury,
        createKey: createKey.publicKey,
        creator: creator.publicKey,
        multisigPda,
        configAuthority: null,
        threshold: 1,
        members: [
            { key: creator.publicKey, permissions: { mask: 1 | 2 | 4 } }, // initiate | vote | execute
        ],
        timeLock: 0,
        rentCollector: null,
        programId: PROGRAM_ID,
    })

    const vaultTransferIx = SystemProgram.transfer({
        fromPubkey: creator.publicKey,
        toPubkey: vaultPda,
        lamports: 0.001 * LAMPORTS_PER_SOL,
    })

    const treasuryTransferIx = SystemProgram.transfer({
        fromPubkey: creator.publicKey,
        toPubkey: treasury,
        lamports: 0.1 * LAMPORTS_PER_SOL,
    })

    const blockhash = (await connection.getLatestBlockhash()).blockhash
    const message = new TransactionMessage({
        payerKey: creator.publicKey,
        recentBlockhash: blockhash,
        instructions: [
      	    createIx,
            vaultTransferIx,
            treasuryTransferIx
        ],
    }).compileToV0Message()

    const tx = new VersionedTransaction(message)
    tx.sign([creator, createKey])
    console.log(tx)

    const sig = await connection.sendTransaction(tx)
    console.log("Multisig PDA:", multisigPda.toBase58())
    console.log("Vault 0 PDA:", vaultPda.toBase58())
    console.log("Signature:", sig)
}

main()
