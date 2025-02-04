package io.moonsglw.moonbase.auth.adapter.util;

import org.keycloak.representations.idm.CredentialRepresentation;
import org.springframework.stereotype.Component;

@Component
public class CredentialsUtil {

	public CredentialRepresentation createPasswordCredentials(String password) {
		CredentialRepresentation passwordCredentials = new CredentialRepresentation();
		passwordCredentials.setTemporary(false);
		passwordCredentials.setType(CredentialRepresentation.PASSWORD);
		passwordCredentials.setValue(password);
		return passwordCredentials;
	}
}
