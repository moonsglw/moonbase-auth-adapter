package io.moonsglw.moonbase.auth.adapter.dto;

import java.util.List;

import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import lombok.Data;

@Data
public class UserWithRolesDTO {

	private UserRepresentation user;
    private List<RoleRepresentation> roles;
}
