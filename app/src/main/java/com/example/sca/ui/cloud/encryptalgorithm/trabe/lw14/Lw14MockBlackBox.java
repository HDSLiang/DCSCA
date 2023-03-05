package com.example.sca.ui.cloud.encryptalgorithm.trabe.lw14;

import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbeDecryptionException;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePrivateKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.AbePublicKey;
import com.example.sca.ui.cloud.encryptalgorithm.trabe.policyparser.ParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class Lw14MockBlackBox extends Lw14DecryptionBlackBox {

    public List<AbePrivateKey> userKeys = new ArrayList<AbePrivateKey>();
    public AbePublicKey publicKey;

    public Lw14MockBlackBox(List<AbePrivateKey> userKeys, AbePublicKey publicKey) {
        this.userKeys = userKeys;
        this.publicKey = publicKey;
    }

    public Lw14MockBlackBox(AbePrivateKey[] userKeys, AbePublicKey publicKey) {
        this.userKeys = new ArrayList<AbePrivateKey>(userKeys.length);
        Collections.addAll(this.userKeys, userKeys);
        this.publicKey = publicKey;
    }

    /**
     * Determine if the given cipher text can be decrypted using this black box.
     *
     * @param ct Cipher text
     * @return is decryptable
     */
    @Override
    public Element decrypt(CipherText ct) {
        for(AbePrivateKey key : userKeys) {
            try {
                if (Lw14.canDecrypt(key, ct)) {
                    return Lw14.decrypt(key, ct);
                }
            } catch (AbeDecryptionException | ParseException e) {

            }
        }
        return null;
    }
}
