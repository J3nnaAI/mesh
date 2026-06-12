// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Node identity: a random v4 UUID plus an ed25519 keypair, persisted in the SAME on-disk format as the Go
// reference so the file is byte-interchangeable — {"id", "priv_b64"} where priv_b64 is base64-std of the
// 64-byte Go private key (32-byte seed ‖ 32-byte public key). The UUID is independent of the key and is what
// a grant binds to, so it must be persisted and reused (regenerating it after enrollment breaks admission).

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.UUID;

public final class Identity {
    public final String id;
    public final byte[] seed;       // 32-byte ed25519 seed (private)
    public final byte[] publicKey;  // 32-byte ed25519 public key

    // X.509 SPKI / PKCS8 fixed prefixes for raw ed25519 keys.
    private static final byte[] PKCS8_PREFIX = Wire.unhex("302e020100300506032b657004220420");

    public Identity(String id, byte[] seed, byte[] publicKey) {
        this.id = id;
        this.seed = seed;
        this.publicKey = publicKey;
    }

    public byte[] sign(byte[] msg) {
        return Wire.sign(privateKey(), msg);
    }

    public String publicKeyB64() {
        return Base64.getEncoder().encodeToString(publicKey);
    }

    public PublicKey publicKeyObj() {
        return Wire.ed25519Pub(publicKey);
    }

    /** Reconstruct a signing key from the persisted 32-byte seed (PKCS8 SPKI wrapper). */
    public PrivateKey privateKey() {
        try {
            byte[] der = new byte[PKCS8_PREFIX.length + seed.length];
            System.arraycopy(PKCS8_PREFIX, 0, der, 0, PKCS8_PREFIX.length);
            System.arraycopy(seed, 0, der, PKCS8_PREFIX.length, seed.length);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Load the identity at `path`, or create + persist (0600) a fresh one. Byte-compatible with Go. */
    public static Identity ensureIdentity(String path) throws IOException {
        Path p = Path.of(path);
        if (Files.exists(p)) {
            JsonObject blob = JsonParser.parseString(Files.readString(p)).getAsJsonObject();
            byte[] raw = Base64.getDecoder().decode(blob.get("priv_b64").getAsString());
            if (raw.length != 64) {
                throw new IllegalStateException("identity priv_b64 must decode to 64 bytes (seed||pubkey)");
            }
            return new Identity(blob.get("id").getAsString(),
                    Arrays.copyOfRange(raw, 0, 32), Arrays.copyOfRange(raw, 32, 64));
        }

        try {
            var kpg = KeyPairGenerator.getInstance("Ed25519");
            var kp = kpg.generateKeyPair();
            // seed = last 32 bytes of the 48-byte PKCS8 encoding; pub = last 32 bytes of the 44-byte X.509.
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            byte[] spki = kp.getPublic().getEncoded();
            byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
            byte[] pub = Arrays.copyOfRange(spki, spki.length - 32, spki.length);

            Identity ident = new Identity(UUID.randomUUID().toString(), seed, pub);

            byte[] combined = new byte[64];
            System.arraycopy(seed, 0, combined, 0, 32);
            System.arraycopy(pub, 0, combined, 32, 32);
            JsonObject blob = new JsonObject();
            blob.addProperty("id", ident.id);
            blob.addProperty("priv_b64", Base64.getEncoder().encodeToString(combined));

            Path dir = p.toAbsolutePath().getParent();
            if (dir != null) Files.createDirectories(dir);

            byte[] data = blob.toString().getBytes(StandardCharsets.UTF_8);
            try {
                // Create with 0600 atomically (no readable window on the private key), like Python's os.open.
                var perms = PosixFilePermissions.asFileAttribute(
                        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                Files.deleteIfExists(p);
                Files.createFile(p, perms);
                Files.write(p, data);
            } catch (UnsupportedOperationException ex) {
                // non-POSIX filesystem; best-effort write then narrow perms.
                Files.write(p, data);
                try {
                    Files.setPosixFilePermissions(p, EnumSet.of(
                            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
                } catch (UnsupportedOperationException ignored) {
                    // truly non-POSIX; nothing more to do
                }
            }
            return ident;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
