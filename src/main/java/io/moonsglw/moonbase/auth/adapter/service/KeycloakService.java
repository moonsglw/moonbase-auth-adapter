package io.moonsglw.moonbase.auth.adapter.service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.ws.rs.core.Response;

import org.hibernate.validator.cfg.context.ReturnValueConstraintMappingContext;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.JsonNode;

import io.moonsglw.moonbase.auth.adapter.config.KeycloakProvider;
import io.moonsglw.moonbase.auth.adapter.dto.DeleteMetaDTO;
import io.moonsglw.moonbase.auth.adapter.dto.ExceptionJSONInfoDTO;
import io.moonsglw.moonbase.auth.adapter.dto.ListMetaDTO;
import io.moonsglw.moonbase.auth.adapter.dto.MainResponseDTO;
import io.moonsglw.moonbase.auth.adapter.dto.TokenResponseDTO;
import io.moonsglw.moonbase.auth.adapter.dto.UserWithRolesDTO;
import io.moonsglw.moonbase.auth.adapter.dto.request.UserRequestDTO;
import io.moonsglw.moonbase.auth.adapter.exception.UnauthorizedException;
import io.moonsglw.moonbase.auth.adapter.util.ClientContext;
import io.moonsglw.moonbase.auth.adapter.util.CredentialsUtil;
import io.moonsglw.moonbase.auth.adapter.util.EmptyNullCheckUtil;
import io.moonsglw.moonbase.auth.adapter.util.UserContext;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class KeycloakService {

	@Value("${keycloak.realm}")
	public String realm;

	@Value("${moonbase.iam.adapter.end.session.endpoint}")
	public String endSessionEndpointPath;

	@Value("${moonbase.iam.adapter.post.logout.uri.param.key}")
	public String postLogoutRedirectURIParamKey;

	@Value("${app.version}")
	private double version;

	@Value("${app.utc-datetime-pattern}")
	private String appDateTimeFormat;

	@Autowired
	private TokenCache tokenCache;

	private final KeycloakProvider kcProvider;

	@Autowired
	private CredentialsUtil credentialsUtil;

	public KeycloakService(KeycloakProvider keycloakProvider) {
		this.kcProvider = keycloakProvider;

	}

	public TokenResponseDTO getToken(String clientId, String clientSecret) {
        String token = tokenCache.getToken(clientId);

        if (token != null && validateToken(token, clientId)) {
            return new TokenResponseDTO(token, tokenCache.getExpiresAt(clientId));
        }
        return generateNewToken(clientId, clientSecret);
    }

	private TokenResponseDTO generateNewToken(String clientId, String clientSecret) {
		try {
            AccessTokenResponse tokenResponse = kcProvider.generateClientToken(clientId, clientSecret);
            String token = tokenResponse.getToken();
            long expiresIn = tokenResponse.getExpiresIn();
            long expiresAt = System.currentTimeMillis() / 1000 + expiresIn;

            // Store in cache
            tokenCache.storeToken(clientId, token, expiresAt);

            return new TokenResponseDTO(token, expiresAt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate new client token", e);
        }
	}

	public boolean validateToken(String token, String clientId) {
        return kcProvider.validateToken(token, clientId);
    }

    public String getClientIdFromToken(String token) {
        return kcProvider.getClientIdFromToken(token);
    }
    
    public boolean validateUserToken(String token) {
        return kcProvider.validateUserToken(token);
    }
    
    public String getUserIdFromToken(String token) {
    	return kcProvider.getUserIdFromToken(token);
    }
    
    public String getUsernameFromToken(String token) {
    	return kcProvider.getUsernameFromToken(token);
    }
    
    public List<String> getUserRolesFromToken(String token) {
    	return kcProvider.getUserRolesFromToken(token);
    }

	public Response createKeycloakUser(UserRequestDTO user) {
		// UsersResource usersResource = kcProvider.getInstance().realm(realm).users();
		CredentialRepresentation credentialRepresentation = credentialsUtil
				.createPasswordCredentials(user.getPassword());

		UserRepresentation kcUser = new UserRepresentation();
		kcUser.setUsername(user.getEmail());
		kcUser.setCredentials(Collections.singletonList(credentialRepresentation));
		kcUser.setFirstName(user.getFirstname());
		kcUser.setLastName(user.getLastname());
		kcUser.setEmail(user.getEmail());
		kcUser.setEnabled(user.isEnabled());
		/* set to true since endpoint will only be accessed by ROLE_ADMIN */
		kcUser.setEmailVerified(true);

		Response response = getUsersResource().create(kcUser);

		if (response.getStatus() == 201) { // User created successfully
			UserRepresentation userRep = getUsersResource().search(user.getUsername()).get(0);
			if (userRep.getUsername() != null) {
				log.info("User with id: " + userRep.getId() + " has been successfully created");
				assignRolesToUser(userRep.getId(), user.getRole(), user.getAttributes());
			} else {
				log.error("User creation succeeded, but the user was not found in the search results.");
			}
		} else {
			log.error("User creation failed with status: " + response.getStatus());
		}

		return response;

	}

	private void assignRolesToUser(String userId, String userRole, Map<String, List<String>> attributes) {
		//String clientId = getAuthorizedClientId();
		String clientId = ClientContext.getClientId();

		try {

			/**
			 * First check for existing role if passed role isnt null, delete it and replace
			 * with passed new role
			 */

			log.info("User ID: " + userId);

			UserResource userResource = getUsersResource().get(userId);
			ClientRepresentation clientRepresentation = getClientsResource().findByClientId(clientId).get(0);

			if (clientRepresentation == null) {
				log.error("Client with clientId " + clientId + " not found.");
				return;
			}

			ClientResource clientResource = getClientsResource().get(clientRepresentation.getId());
			List<RoleRepresentation> roles = clientResource.roles().list();
			RoleRepresentation roleRepresentation = roles.stream().filter(role -> role.getName().equals(userRole))
					.findFirst().orElse(null);

			if (roleRepresentation == null) {
				log.error("Role " + userRole + " not found for client " + clientId);
				return;
			}
			userResource.roles().clientLevel(clientRepresentation.getId())
					.add(Collections.singletonList(roleRepresentation));
			addAttritubesToUser(userId, userResource, attributes);

			log.info("Role " + userRole + " assigned to user with ID " + userId);

		} catch (Exception e) {
			log.error("Error assigning role to user: " + e.getMessage(), e);
		}
	}

	private void addAttritubesToUser(String userId, UserResource userResource, Map<String, List<String>> attributes) {

		UserRepresentation userRep = userResource.toRepresentation();

		try {
			Map<String, List<String>> existingAttributes = userRep.getAttributes();
			if (existingAttributes == null) {
				existingAttributes = new HashMap<>();
			}
			existingAttributes.putAll(attributes);
			userRep.setAttributes(existingAttributes);
			userResource.update(userRep);
			log.info("Attributes have been successfully added to user with ID " + userId);
		} catch (Exception e) {
			log.error("Error adding attributes to user: " + e.getMessage(), e);
		}

	}

	public void updateUser(String userId, UserRequestDTO userDTO) {

		if (!Objects.isNull(userDTO)) {
			// UsersResource usersResource = kcProvider.getInstance().realm(realm).users();
			UserResource userResource = getUsersResource().get(userId);

			// check if user is
			if (userResource != null) {
				UserRepresentation updatingUser = new UserRepresentation();
				if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
					CredentialRepresentation credential = credentialsUtil
							.createPasswordCredentials(userDTO.getPassword());
					updatingUser.setCredentials(Collections.singletonList(credential));
				}

				updatingUser.setFirstName(userDTO.getFirstname());
				updatingUser.setLastName(userDTO.getLastname());
				updatingUser.setEmail(userDTO.getEmail());
				updatingUser.setUsername(userDTO.getUsername());
				updatingUser.setEnabled(userDTO.isEnabled());

				getUsersResource().get(userId).update(updatingUser);

				assignRolesToUser(userId, userDTO.getRole(), userDTO.getAttributes());
			} else {
				log.error("Error updating user with ID: " + userId + ". User not found");
			}

		}

	}

	public UserRepresentation getUser(String userId) {
		UserResource userResource = getUsersResource().get(userId);
		UserRepresentation user = userResource.toRepresentation();
		return user;

	}

	public boolean checkIfUserExistsByEmail(String emailId) {

		List<UserRepresentation> users = getUsersResource().search(emailId);
		if (users != null && !users.isEmpty()) {

			for (UserRepresentation user : users) {
				if (emailId.equalsIgnoreCase(user.getEmail())) {
					return true;
				}
			}
		}

		return false;

	}

	public List<RoleRepresentation> getUserRoles(String userId) {
		UserResource userResource = getUsersResource().get(userId);
		RoleMappingResource roleMappingResource = userResource.roles();
		// either realmLevel or clientLevel
		RoleScopeResource roleScopeResource = roleMappingResource.clientLevel(getClientUuid());
		return roleScopeResource.listAll();
	}

	public void deleteKeycloakUser(String username) {
		List<UserRepresentation> userList = getUsersResource().search(username);
		for (UserRepresentation user : userList) {
			if (user.getUsername().equals(username)) {
				getUsersResource().delete(user.getId());
			}
		}
	}

	private String getClientUuid() {
		//String clientId = getAuthorizedClientId();
		String clientId = ClientContext.getClientId();
		ClientRepresentation clientRepresentation = getClientsResource().findByClientId(clientId).get(0);
		return clientRepresentation.getId();
	}

	public Map<String, List<String>> getUserAttributes(String userId) {
		UserResource userResource = getUsersResource().get(userId);

		if (userResource != null) {
			UserRepresentation userRep = userResource.toRepresentation();
			Map<String, List<String>> existingAttributes = userRep.getAttributes();
			return existingAttributes;
		} else {
			return null;
		}

	}

	public Map<String, List<String>> getUserAttributesUsingEmail(String emailId) {

		List<UserRepresentation> users = getUsersResource().search(emailId);
		if (users != null && !users.isEmpty()) {

			for (UserRepresentation user : users) {
				if (emailId.equalsIgnoreCase(user.getEmail())) {
					Map<String, List<String>> existingAttributes = user.getAttributes();
					return existingAttributes;
				}
			}
		}

		return null;
	}

	private UsersResource getUsersResource() {
		return kcProvider.getInstance().realm(realm).users();
	}

	private ClientsResource getClientsResource() {
		return kcProvider.getInstance().realm(realm).clients();
	}

	// List all users
	public MainResponseDTO<ListMetaDTO<UserWithRolesDTO>> listUsersByClientId() {
		//String clientId = getAuthorizedClientId();
		String clientId = ClientContext.getClientId();

		MainResponseDTO<ListMetaDTO<UserWithRolesDTO>> response = new MainResponseDTO<>();
		ListMetaDTO<UserWithRolesDTO> listMetaDTO = new ListMetaDTO<>();
		List<ExceptionJSONInfoDTO> explist = new ArrayList<>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		response.setVersion(String.valueOf(version));
		response.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		try {
			ClientRepresentation clientRepresentation = getClientsResource().findByClientId(clientId).get(0);
			if (clientRepresentation == null) {
				log.error("Client with clientId " + clientId + " not found.");
				exception.setMessage("Client with clientId " + clientId + " not found.");
				explist.add(exception);
				response.setErrors(explist);
				return response;
			}

			String clientUuid = clientRepresentation.getId(); // Get the client's UUID

			ClientResource clientResource = getClientsResource().get(clientUuid);
			List<UserWithRolesDTO> usersWithRoles = new ArrayList<>();

			List<RoleRepresentation> clientRoles = clientResource.roles().list(); // Get only roles for this client

			for (RoleRepresentation roleRepresentation : clientRoles) {
				// Exclude Keycloak realm-wide roles
				if (!roleRepresentation.getContainerId().equals(clientUuid)) {
					continue;
				}

				Set<UserRepresentation> usersForRole = clientResource.roles().get(roleRepresentation.getName())
						.getRoleUserMembers();

				for (UserRepresentation user : usersForRole) {
					// Check if user is already in the list
					UserWithRolesDTO userWithRoles = usersWithRoles.stream()
							.filter(u -> u.getUser().getId().equals(user.getId())).findFirst().orElse(null);

					if (userWithRoles == null) {
						userWithRoles = new UserWithRolesDTO();
						userWithRoles.setUser(user);
						userWithRoles.setRoles(new ArrayList<>());
						usersWithRoles.add(userWithRoles);
					}

					// Add role to the user's roles list
					userWithRoles.getRoles().add(roleRepresentation);
				}
			}

			log.info("Fetched " + usersWithRoles.size() + " users for client with ID: " + clientId);
			listMetaDTO.setRecordsList(usersWithRoles);
			listMetaDTO.setTotalRecords(usersWithRoles.size());
			response.setResponse(listMetaDTO);
		} catch (Exception e) {
			log.error("Error listing users for client ID: " + clientId, e);
			exception.setMessage("Error listing users for client ID: " + clientId);
			explist.add(exception);
			response.setErrors(explist);
		}

		return response;
	}

	public MainResponseDTO<ListMetaDTO<String>> listRolesByClientId() {

		//String clientId = getAuthorizedClientId();
		String clientId = ClientContext.getClientId();

		MainResponseDTO<ListMetaDTO<String>> response = new MainResponseDTO<>();
		ListMetaDTO<String> listMetaDTO = new ListMetaDTO<>();

		List<ExceptionJSONInfoDTO> explist = new ArrayList<>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		response.setVersion(String.valueOf(version));
		response.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		try {
			ClientRepresentation clientRepresentation = getClientsResource().findByClientId(clientId).get(0);

			if (clientRepresentation == null) {
				log.error("Client with clientId " + clientId + " not found.");
			} else {
				ClientResource clientResource = getClientsResource().get(clientRepresentation.getId());
				List<String> rolesForClient = new ArrayList<>();

				List<RoleRepresentation> roles = clientResource.roles().list();

				for (RoleRepresentation role : roles) {
					rolesForClient.add(role.getName());
				}

				log.info("Fetched " + rolesForClient.size() + " roles for client with ID: " + clientId);

				listMetaDTO.setRecordsList(rolesForClient);
				listMetaDTO.setTotalRecords(rolesForClient.size());
				response.setResponse(listMetaDTO);
			}
		} catch (Exception e) {
			log.error("Error listing roles for client ID: " + clientId, e);

			exception.setMessage("Error listing roles for client ID: " + clientId);
			explist.add(exception);
			response.setErrors(explist);
		}

		return response;
	}

	// Delete user
	public MainResponseDTO<DeleteMetaDTO> deleteUserByEmail(String email) {
		MainResponseDTO<DeleteMetaDTO> response = new MainResponseDTO<>();
		DeleteMetaDTO deleteMetaDTO = new DeleteMetaDTO();
		List<ExceptionJSONInfoDTO> explist = new ArrayList<>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		response.setVersion(String.valueOf(version));
		response.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		try {
			// Search for users by email
			List<UserRepresentation> users = getUsersResource().search(email);

			if (users.isEmpty()) {
				deleteMetaDTO.setDeleteStatus(false);
				exception.setMessage("User with email " + email + " not found.");
				explist.add(exception);
				response.setErrors(explist);
			} else {
				// Assume email is unique, so we take the first user found
				UserRepresentation userToDelete = users.get(0);

				// Get the UserResource for the found user
				UserResource userResource = getUsersResource().get(userToDelete.getId());

				// Delete the user
				userResource.remove();

				// Set success response
				deleteMetaDTO.setDeleteStatus(true);
				deleteMetaDTO.setId(email);
			}
			response.setResponse(deleteMetaDTO);
		} catch (Exception e) {
			log.error("Error deleting user with email: " + email, e);
			exception.setMessage("Error deleting user with email: " + email);
			explist.add(exception);
			response.setErrors(explist);
		}

		return response;
	}


}
