package sample.webauthn.rp.login;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginFlowRepository extends JpaRepository<LoginFlowEntity, UUID> {}
