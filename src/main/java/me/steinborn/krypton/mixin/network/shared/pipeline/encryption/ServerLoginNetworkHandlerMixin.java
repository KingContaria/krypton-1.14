package me.steinborn.krypton.mixin.network.shared.pipeline.encryption;

import me.steinborn.krypton.mod.shared.network.ClientConnectionEncryptionExtension;
import net.minecraft.network.ClientConnection;
import net.minecraft.network.packet.c2s.login.LoginKeyC2SPacket;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

@Mixin(ServerLoginNetworkHandler.class)
public class ServerLoginNetworkHandlerMixin {
    @Shadow private SecretKey secretKey;

    @Shadow @Final public ClientConnection connection;

    @Inject(method = "onKey", at = @At(value = "FIELD", target = "Lnet/minecraft/server/network/ServerLoginNetworkHandler;secretKey:Ljavax/crypto/SecretKey;", ordinal = 1))
    public void onKey$initializeVelocityCipher(LoginKeyC2SPacket packet, CallbackInfo info) throws GeneralSecurityException {
        ((ClientConnectionEncryptionExtension) this.connection).setupEncryption(this.secretKey);
    }

    @Redirect(method = "onKey", at = @At(value = "INVOKE", target = "Lnet/minecraft/network/ClientConnection;setupEncryption(Ljavax/crypto/SecretKey;)V"))
    public void onKey$ignoreMinecraftEncryptionPipelineInjection(ClientConnection connection, SecretKey ignored) {
        // Turn the operation into a no-op.
    }
}
