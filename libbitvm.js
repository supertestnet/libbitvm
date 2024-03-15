var libbitvm = {
    network: "regtest",
    utxo: {},
    sigs: [],
    scripts: [],
    trees: [],
    contract: [],
    instructions: [],
    addresses: [],
    convertAddress: ( address, type_to_convert_to ) => tapscript.Address.fromScriptPubKey( 
        tapscript.Address.toScriptPubKey( address ), type_to_convert_to
    ),
    hexToBytes: hex => Uint8Array.from( hex.match( /.{1,2}/g ).map( byte => parseInt( byte, 16 ) ) ),
    bytesToHex: bytes => bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" ),
    hexToBinary: hex => {
        var array_hex = hex.match( /\w{2}/g );
        var array_bin = [];
        array_hex.forEach( item => array_bin.push( ( parseInt( item, 16 ).toString( 2 ) ).padStart( 8, '0' ) ) );
        return array_bin.join( "" );
    },
    binaryToHex: binary => {
        var hex = parseInt( binary, 2 ).toString( 16 );
        if ( hex.length % 2 ) hex = "0" + hex;
        return hex;
    },
    numToBinary: num => {
        var binary = num.toString( 2 );
        var i; for ( i=0; i<8; i++ ) if ( binary.length % 8 ) binary = "0" + binary;
        return binary;
    },
    getVin: ( txid, vout, amnt, addy ) => ({
        txid,
        vout,
        prevout: {
            value: amnt,
            scriptPubKey: tapscript.Address.toScriptPubKey( addy ),
        },
    }),
    getVout: ( amnt, addy ) => ({
        value: amnt,
        scriptPubKey: tapscript.Address.toScriptPubKey( addy ),
    }),
    makeActor: pubkey => {
        return {
            pubkey,
            preimages: [],
            hashes: [],
            preimages_used: -1,
            hashes_used: -1,
        }
    },
    makeAddress: {
        challenge: additional_scripts => {
            if ( !libbitvm.prover || !libbitvm.verifier ) throw new Error( `Prover and Verifier not initialized!` );
            var scripts = [
                [ libbitvm.prover[ "pubkey" ], "OP_CHECKSIG", libbitvm.verifier[ "pubkey" ], "OP_CHECKSIGADD", 2, "OP_EQUAL" ],
                [ 10, "OP_CHECKSEQUENCEVERIFY", libbitvm.verifier[ "pubkey" ], "OP_CHECKSIG" ],
            ];
            if ( additional_scripts ) scripts.push( ...additional_scripts );
            //allow the prover to take the verifier's money if the
            //verifier contradicts herself
            var i; for ( i=0; i<libbitvm.verifier.hashes.length; i=i+2 ) {
                var pair = [ libbitvm.verifier.hashes[ i ], libbitvm.verifier.hashes[ i+1 ] ];
                var script = [
                    "OP_SHA256",
                    "OP_SWAP",
                    "OP_SHA256",
                    pair[ 0 ],
                    "OP_EQUALVERIFY",
                    pair[ 1 ],
                    "OP_EQUALVERIFY",
                    libbitvm.prover.pubkey,
                    "OP_CHECKSIG",
                ];
                scripts.push( script );
            }
            var tree = scripts.map( s => tapscript.Tap.encodeScript( s ) );
            var pubkey = "ab".repeat( 32 );
            var [ tpubkey ] = tapscript.Tap.getPubKey( pubkey, { tree });
            var address = tapscript.Address.p2tr.fromPubKey( tpubkey, libbitvm.network );
            libbitvm.scripts.push( scripts );
            libbitvm.trees.push( tree );
            libbitvm.addresses.push( address );
            return address;
        },
        response: additional_scripts => {
            if ( !libbitvm.prover || !libbitvm.verifier ) throw new Error( `Prover and Verifier not initialized!` );
            var scripts = [
                [ libbitvm.prover[ "pubkey" ], "OP_CHECKSIG", libbitvm.verifier[ "pubkey" ], "OP_CHECKSIGADD", 2, "OP_EQUAL" ],
                [ 10, "OP_CHECKSEQUENCEVERIFY", libbitvm.prover[ "pubkey" ], "OP_CHECKSIG" ],
            ];
            if ( additional_scripts ) scripts.push( ...additional_scripts );
            //allow the verifier to take the prover's money if the
            //prover contradicts himself
            var i; for ( i=0; i<libbitvm.prover.hashes.length; i=i+2 ) {
                var pair = [ libbitvm.prover.hashes[ i ], libbitvm.prover.hashes[ i+1 ] ];
                var script = [
                    "OP_SHA256",
                    "OP_SWAP",
                    "OP_SHA256",
                    pair[ 0 ],
                    "OP_EQUALVERIFY",
                    pair[ 1 ],
                    "OP_EQUALVERIFY",
                    libbitvm.verifier.pubkey,
                    "OP_CHECKSIG",
                ];
                scripts.push( script );
            }
            var tree = scripts.map( s => tapscript.Tap.encodeScript( s ) );
            var pubkey = "ab".repeat( 32 );
            var [ tpubkey ] = tapscript.Tap.getPubKey( pubkey, { tree });
            var address = tapscript.Address.p2tr.fromPubKey( tpubkey, libbitvm.network );
            libbitvm.scripts.push( scripts );
            libbitvm.trees.push( tree );
            libbitvm.addresses.push( address );
            return address;
        }
    },
    getInOutInfo: index => {
        if ( !index ) {
            var txid = libbitvm.utxo[ "txid" ];
            var vout = libbitvm.utxo[ "vout" ];
            var amnt = libbitvm.utxo[ "amnt" ];
            var addy = libbitvm.utxo[ "addy" ];
            var to_addy = libbitvm.addresses[ index + 1 ];
        } else {
            var txid = libbitvm.contract[ index - 1 ][ "txid" ];
            var vout = libbitvm.contract[ index - 1 ][ "vout" ];
            var amnt = libbitvm.contract[ index - 1 ][ "amnt" ];
            var addy = libbitvm.contract[ index - 1 ][ "addy" ];
            if ( index != libbitvm.addresses.length - 1 ) var to_addy = libbitvm.addresses[ index + 1 ];
            else var to_addy = "tb1qd28npep0s8frcm3y7dxqajkcy2m40eysplyr9v";
        }
        return [ txid, vout, amnt, addy, to_addy ];
    },
    makeContract: async ( outputs_to_use_on_last_tx ) => {
        if ( !libbitvm.addresses.length ) throw new Error( `Addresses not prepared!` );
        if ( !libbitvm.utxo ) throw new Error( `Funding utxo not prepared!` );
        if ( !libbitvm.prover || !libbitvm.verifier ) throw new Error( `Prover and Verifier not initialized!` );
        libbitvm.addresses.forEach( ( _, index ) => {
            var [ txid, vout, amnt, addy, to_addy ] = libbitvm.getInOutInfo( index );
            var tx = {
                vin: [libbitvm.getVin( txid, vout, amnt, addy )],
                //todo: estimate the actual fee cost and include anchors
                vout: [libbitvm.getVout( amnt - 10_000, to_addy )],
            }
            var txdata = tapscript.Tx.create( tx );
            var new_txid = tapscript.Tx.util.getTxid( txdata );
            libbitvm.contract[ index ] = {
                txid: new_txid,
                vout: 0,
                amnt: amnt - 10_000,
                addy: to_addy,
            }
        });
        var i; for ( i=0; i<libbitvm.contract.length; i++ ) {
            var index = i;
            var item = libbitvm.contract[ i ];
            var amnt = item.amnt;
            //TODO: each party should only give their signature for txs
            //"belonging to" their opponent. E.g. Vicky must cosign in
            //advance to let Paul move the money from address 0 to address
            //1 but Vicky needn't then give her signature moving the money
            //from address 1 to address 2. Paul must do the reverse: he
            //needn't cosign in advance to move the money from address 0 to
            //address 1 but he must to do so for address 1 to address 2
            //(otherwise he could withhold his sig and prevent Vicky from
            //taking her turn til her timelock expires, at which point Paul
            //could take back his collateral without performing the full
            //computation)
            if ( index % 2 ) var tapleaf_to_use = 0;
            else var tapleaf_to_use = 2;
            if ( libbitvm.prover.privkey ) {
                if ( index == libbitvm.addresses.length - 1 ) {
                    var sig_1 = libbitvm.signContractTx( libbitvm.prover.privkey, index, tapleaf_to_use, outputs_to_use_on_last_tx );
                    var sig_1_is_valid = await libbitvm.checkSig( sig_1, libbitvm.prover.pubkey, index, tapleaf_to_use, outputs_to_use_on_last_tx );
                } else {
                    var sig_1 = libbitvm.signContractTx( libbitvm.prover.privkey, index, tapleaf_to_use );
                    var sig_1_is_valid = await libbitvm.checkSig( sig_1, libbitvm.prover.pubkey, index, tapleaf_to_use );
                }
            }
            if ( libbitvm.verifier.privkey ) {
                if ( index == libbitvm.addresses.length - 1 ) {
                    var sig_2 = libbitvm.signContractTx( libbitvm.verifier.privkey, index, tapleaf_to_use, outputs_to_use_on_last_tx );
                    var sig_2_is_valid = await libbitvm.checkSig( sig_2, libbitvm.verifier.pubkey, index, tapleaf_to_use, outputs_to_use_on_last_tx );
                } else {
                    var sig_2 = libbitvm.signContractTx( libbitvm.verifier.privkey, index, tapleaf_to_use );
                    var sig_2_is_valid = await libbitvm.checkSig( sig_2, libbitvm.verifier.pubkey, index, tapleaf_to_use );
                }
            }
            var [ txid, vout, amnt, addy, to_addy ] = libbitvm.getInOutInfo( index );
            var tx = {
                vin: [libbitvm.getVin( txid, vout, amnt, addy )],
                //todo: estimate the actual fee cost and include anchors
                vout: [libbitvm.getVout( amnt - 10_000, to_addy )],
            }
            if ( outputs_to_use_on_last_tx && index === libbitvm.contract.length - 1 ) tx[ "vout" ] = outputs_to_use_on_last_tx;
            if ( libbitvm.prover.privkey ) libbitvm.sigs.push( [ sig_1, tx ] );
            if ( libbitvm.verifier.privkey ) libbitvm.sigs.push( [ sig_2, tx ] );
        }
    },
    importSigs: () => prompt( `Please enter your counterparty's signatures in this format: ['verifier', 'sig_for_tx_1', 'sig_for_tx_2'...] where the first element is "prover" or "verifier", depending on which role they are playing` ),
    signContractTx: ( privkey, contract_index, tapleaf_index, outputs ) => {
        var [ txid, vout, amnt, addy, to_addy ] = libbitvm.getInOutInfo( contract_index );
        var tx = {
            vin: [libbitvm.getVin( txid, vout, amnt, addy )],
            //todo: estimate the actual fee cost and include anchors
            vout: [libbitvm.getVout( amnt - 10_000, to_addy )],
        }
        if ( outputs ) tx[ "vout" ] = outputs;
        var txdata = tapscript.Tx.create( tx );
        var scripts = libbitvm.scripts[ contract_index ];
        var target = tapscript.Tap.encodeScript( scripts[ tapleaf_index ] );
        var sig = tapscript.Signer.taproot.sign( privkey, txdata, 0, { extension: target }).hex;
        return sig;
    },
    checkSig: async ( sig, pubkey, contract_index, tapleaf_index, outputs ) => {
        var [ txid, vout, amnt, addy, to_addy ] = libbitvm.getInOutInfo( contract_index );
        var tx = {
            vin: [libbitvm.getVin( txid, vout, amnt, addy )],
            //todo: estimate the actual fee cost and include anchors
            vout: [libbitvm.getVout( amnt - 10_000, to_addy )],
        }
        if ( outputs ) tx[ "vout" ] = outputs;
        var txdata = tapscript.Tx.create( tx );
        var scripts = libbitvm.scripts[ contract_index ];
        var target = tapscript.Tap.encodeScript( scripts[ tapleaf_index ] );
        var sighash = tapscript.Signer.taproot.hash( txdata, 0, { extension: target }).hex;
        var sig_is_valid = await nobleSecp256k1.schnorr.verify( sig, sighash, pubkey );
        return sig_is_valid;
    },
    functions: {
        push_bit: player => {
            var hashes_needed = 2;
            if ( !player.hashes[ player.hashes_used + hashes_needed ] ) {
                var preimage = nobleSecp256k1.utils.randomPrivateKey();
                var hash = sha256( preimage );
                player.preimages.push( libbitvm.bytesToHex( preimage ) );
                player.hashes.push( libbitvm.bytesToHex( hash ) );
                return libbitvm.functions.push_bit( player );
            }
            var script = [
                "OP_SHA256",
                "OP_DUP",
                player.hashes[ player.hashes_used + 1 ],
                "OP_EQUAL",
                "OP_IF",
                    "OP_DROP",
                    "OP_0",
                "OP_ELSE",
                    player.hashes[ player.hashes_used + 2 ],
                    "OP_EQUALVERIFY",
                    "OP_1",
                "OP_ENDIF"
            ]
            player.hashes_used = player.hashes_used + hashes_needed;
            return script;
        },
        reveal_bit: ( player, bit_to_reveal ) => {
            var next = player.preimages_used + 1;
            var pair = [ player.preimages[ next ], player.preimages[ next + 1 ] ];
            player.preimages_used = player.preimages_used + 2;
            return pair[ bit_to_reveal ];
        },
        push_byte: player => {
            var script = [];
            var i; for ( i=0; i<8; i++ ) {
                script.push( ...libbitvm.functions.push_bit( player ) );
                script.push( "OP_TOALTSTACK" );
            }
            var i; for ( i=0; i<8; i++ ) script.push( "OP_FROMALTSTACK" );
            var num = 1;
            var i; for ( i=0; i<7; i++ ) {
                script.push( 
                    `OP_${num}`,
                    "OP_ROLL",
                );
                num = num + 1;
            }
            script.push( ...libbitvm.functions.recompose_number() );
            return script;
        },
        reveal_byte: ( player, byte_to_reveal ) => {
            var binary = libbitvm.hexToBinary( byte_to_reveal );
            binary = binary.split( "" ).map( Number );
            var preimages_to_reveal = [];
            var i; for ( i of binary ) preimages_to_reveal.push( libbitvm.functions.reveal_bit( player, binary[ i ] ) );
            return preimages_to_reveal;
        },
        push_10_bytes: player => {
            var script = [];
            var i; for ( i=0; i<10; i++ ) {
                script.push( ...libbitvm.functions.push_byte( player ) );
            }
            return script;
        },
        reveal_10_bytes: ( player, ten_bytes ) => {
            var binary = libbitvm.hexToBinary( ten_bytes );
            var binary_array = binary.match( /\w{8}/g );
            var preimages_to_reveal = [];
            binary_array.forEach( item => {
                item = item.split( "" ).map( Number );
                var i; for ( i of item ) preimages_to_reveal.push( libbitvm.functions.reveal_bit( player, item[ i ] ) );
            });
            return preimages_to_reveal;
        },
        push_20_bytes: player => {
            var script = [];
            var i; for ( i=0; i<20; i++ ) {
                script.push( ...libbitvm.functions.push_byte( player ) );
            }
            return script;
        },
        reveal_20_bytes: ( player, twenty_bytes ) => libbitvm.functions.reveal_10_bytes( player, twenty_bytes ),
        push_32_bytes: player => {
            var script = [];
            var i; for ( i=0; i<32; i++ ) {
                script.push( ...libbitvm.functions.push_byte( player ) );
            }
            return script;
        },
        reveal_32_bytes: ( player, twenty_bytes ) => libbitvm.functions.reveal_10_bytes( player, twenty_bytes ),
        decompose_number: () => [
            "OP_DUP",
            128,
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            128,
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            64,
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            64,
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            32,
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            32,
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            "OP_16",
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            "OP_16",
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            "OP_8",
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            "OP_8",
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            "OP_4",
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            "OP_4",
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_DUP",
            "OP_2",
            "OP_GREATERTHANOREQUAL",
            "OP_DUP",
            "OP_IF",
            "OP_SWAP",
            "OP_2",
            "OP_SUB",
            "OP_SWAP",
            "OP_ENDIF",
            "OP_TOALTSTACK",
            "OP_1",
            "OP_GREATERTHANOREQUAL",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
        ],
        recompose_number: () => [
            "OP_TOALTSTACK",
            "OP_IF",
                "OP_2",
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                "OP_4",
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                "OP_8",
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                "OP_16",
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                32,
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                64,
                "OP_TOALTSTACK",
            "OP_ELSE",
                "OP_0",
                "OP_TOALTSTACK",
            "OP_ENDIF",
            "OP_IF",
                128,
            "OP_ELSE",
                "OP_0",
            "OP_ENDIF",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_ADD",
            "OP_ADD",
            "OP_ADD",
            "OP_ADD",
            "OP_ADD",
            "OP_ADD",
            "OP_ADD",
            "OP_TOALTSTACK",
        ],
        line_up_bytes: () => [
            "OP_8",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_7",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_6",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_5",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_4",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_3",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_2",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_TOALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_15",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_14",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_13",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_12",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_11",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_10",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_9",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_8",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_7",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_6",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_5",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_4",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_3",
            "OP_ROLL",
            "OP_TOALTSTACK",
            "OP_2",
            "OP_ROLL",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
        ],
        logical_and: () => [
            "OP_FROMALTSTACK",
            ...libbitvm.functions.decompose_number(),
            "OP_FROMALTSTACK",
            ...libbitvm.functions.decompose_number(),
            ...libbitvm.functions.line_up_bytes(),
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_TOALTSTACK",
            "OP_BOOLAND",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            ...libbitvm.functions.recompose_number(),
        ],
        logical_or: () => [
            "OP_FROMALTSTACK",
            ...libbitvm.functions.decompose_number(),
            "OP_FROMALTSTACK",
            ...libbitvm.functions.decompose_number(),
            ...libbitvm.functions.line_up_bytes(),
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_TOALTSTACK",
            "OP_BOOLOR",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            "OP_FROMALTSTACK",
            ...libbitvm.functions.recompose_number(),
        ],
    }
    // var recompose_number = [
    // ];
    // console.log( recompose_number );
    // var address = tapscript.Address.p2wsh.fromScript( recompose_number, lbv.network );
    // console.log( address );
    // var txid = prompt( `send some sats to this address and give the txid:\n\n${address}` );
    // var vout = Number( prompt( `and the vout` ) );
    // var amnt = Number( prompt( `and the amount` ) );
    // var addy = address;
    // var to_addy = "bcrt1q4jn7c0q2glt93pfhzcl8xh6qu7dc82u5j0rjuh";
    // var tx = {
    //     vin: [libbitvm.getVin( txid, vout, amnt, addy )],
    //     vout: [libbitvm.getVout( amnt - 500, to_addy )],
    // }
    // var txdata = tapscript.Tx.create( tx );
    // test_txdata = txdata;
    // txdata.vin[0].witness = [ 0, 0, 0, 0, 0, 0, 0, 0, recompose_number ];
    // var txhex = tapscript.Tx.encode( txdata ).hex;
    // console.log( "txhex:", txhex );
}