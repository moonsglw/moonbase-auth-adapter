package io.moonsglw.moonbase.auth.adapter.controller;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.moonsglw.moonbase.auth.adapter.config.KeycloakProvider;
import io.moonsglw.moonbase.auth.adapter.dto.DeleteMetaDTO;
import io.moonsglw.moonbase.auth.adapter.dto.ExceptionJSONInfoDTO;
import io.moonsglw.moonbase.auth.adapter.dto.ListMetaDTO;
import io.moonsglw.moonbase.auth.adapter.dto.MainResponseDTO;
import io.moonsglw.moonbase.auth.adapter.dto.CreateAndUpdateMetaDTO;
import io.moonsglw.moonbase.auth.adapter.dto.UserLoginRequestDTO;
import io.moonsglw.moonbase.auth.adapter.dto.UserWithRolesDTO;
import io.moonsglw.moonbase.auth.adapter.dto.request.UserRequestDTO;
import io.moonsglw.moonbase.auth.adapter.intrface.RequiresAuth;
import io.moonsglw.moonbase.auth.adapter.service.KeycloakService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/users")
public class UserController {

	private final KeycloakService kcAdminClient;

	private final KeycloakProvider kcProvider;

	@Value("${app.utc-datetime-pattern}")
	private String appDateTimeFormat;

	@Value("${app.version}")
	private double version;

	public UserController(KeycloakService kcAdminClient, KeycloakProvider kcProvider) {
		this.kcProvider = kcProvider;
		this.kcAdminClient = kcAdminClient;
	}

	@PostMapping("/create")
	@RequiresAuth
	public ResponseEntity<MainResponseDTO<CreateAndUpdateMetaDTO<?>>> createUser(@RequestBody UserRequestDTO user) {
		MainResponseDTO<CreateAndUpdateMetaDTO<?>> responseDto = new MainResponseDTO<CreateAndUpdateMetaDTO<?>>();
		CreateAndUpdateMetaDTO<String> createMetaDTO = new CreateAndUpdateMetaDTO<String>();
		Response createdResponse = null;
		List<ExceptionJSONInfoDTO> explist = new ArrayList<ExceptionJSONInfoDTO>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		responseDto.setVersion(String.valueOf(version));
		responseDto.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		try {
			createdResponse = kcAdminClient.createKeycloakUser(user);
			if (createdResponse.getStatus() == 201) {
				createMetaDTO.setStatus(true);
				responseDto.setResponse(createMetaDTO);
			} else if (createdResponse.getStatus() == 409) {
				exception.setMessage("User id already exists");
				explist.add(exception);
				responseDto.setErrors(explist);
			}
		} catch (BadRequestException e) {
			exception.setMessage(e.getMessage());
			explist.add(exception);
			responseDto.setErrors(explist);
		}
		return ResponseEntity.status(HttpStatus.OK).body(responseDto);
	}

	@PostMapping("/login")
	@RequiresAuth
	public ResponseEntity<AccessTokenResponse> login(@NotNull @RequestBody UserLoginRequestDTO loginRequest,
			HttpServletResponse response) {
		Keycloak keycloak = kcProvider
				.newKeycloakBuilderWithPasswordCredentials(loginRequest.getUsername(), loginRequest.getPassword())
				.build();

		AccessTokenResponse accessTokenResponse = null;

		try {
			accessTokenResponse = keycloak.tokenManager().getAccessToken();
			return ResponseEntity.status(HttpStatus.OK).body(accessTokenResponse);
		} catch (BadRequestException ex) {
			log.warn("invalid account. User probably hasn't verified email.", ex);

			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(accessTokenResponse);
		}
	}

	@PutMapping("/update/{userId}")
	@RequiresAuth
	public ResponseEntity<MainResponseDTO<CreateAndUpdateMetaDTO<String>>> updateUser(
			@PathVariable("userId") String userId, @RequestBody UserRequestDTO userDTO) {

		MainResponseDTO<CreateAndUpdateMetaDTO<String>> mainResponseDTO = new MainResponseDTO<CreateAndUpdateMetaDTO<String>>();
		CreateAndUpdateMetaDTO<String> updateMetaDTO = new CreateAndUpdateMetaDTO<String>();

		mainResponseDTO.setVersion(String.valueOf(version));
		mainResponseDTO.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		List<ExceptionJSONInfoDTO> explist = new ArrayList<ExceptionJSONInfoDTO>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		String message = null;

		try {

			kcAdminClient.updateUser(userId, userDTO);
			message = "Successfully updated user with ID : " + userId;
			updateMetaDTO.setStatus(true);
			updateMetaDTO.setData(message);
			mainResponseDTO.setResponse(updateMetaDTO);

		} catch (BadRequestException e) {
			// message = e.getMessage();
			exception.setMessage(e.getMessage());
			explist.add(exception);
			mainResponseDTO.setErrors(explist);
		}

		return ResponseEntity.status(HttpStatus.OK).body(mainResponseDTO);
	}

	@GetMapping("/{userId}")
	@RequiresAuth
	public ResponseEntity<MainResponseDTO<UserRepresentation>> getUser(@PathVariable("userId") String userId) {

		MainResponseDTO<UserRepresentation> mainResponseDTO = new MainResponseDTO<UserRepresentation>();

		mainResponseDTO.setVersion(String.valueOf(version));
		mainResponseDTO.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		List<ExceptionJSONInfoDTO> explist = new ArrayList<ExceptionJSONInfoDTO>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		try {

			UserRepresentation user = kcAdminClient.getUser(userId);
			mainResponseDTO.setResponse(user);

		} catch (BadRequestException e) {
			// message = e.getMessage();
			exception.setMessage(e.getMessage());
			explist.add(exception);
			mainResponseDTO.setErrors(explist);
		}

		return ResponseEntity.status(HttpStatus.OK).body(mainResponseDTO);

	}

	@GetMapping("/roles/{userId}")
	@RequiresAuth
	public ResponseEntity<MainResponseDTO<List<String>>> getUserRoles(@PathVariable("userId") String userId) {

		MainResponseDTO<List<String>> mainResponseDTO = new MainResponseDTO<List<String>>();

		mainResponseDTO.setVersion(String.valueOf(version));
		mainResponseDTO.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		List<ExceptionJSONInfoDTO> explist = new ArrayList<ExceptionJSONInfoDTO>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		try {

			List<RoleRepresentation> listUserRoles = kcAdminClient.getUserRoles(userId);
			List<String> listRolesStrings = listUserRoles.stream().map(RoleRepresentation::getName)
					.collect(Collectors.toList());
			mainResponseDTO.setResponse(listRolesStrings);

		} catch (BadRequestException e) {
			// message = e.getMessage();
			exception.setMessage(e.getMessage());
			explist.add(exception);
			mainResponseDTO.setErrors(explist);
		}

		return ResponseEntity.status(HttpStatus.OK).body(mainResponseDTO);
	}

	@GetMapping("/attributes/{userId}")
	@RequiresAuth
	public ResponseEntity<MainResponseDTO<Map<String, List<String>>>> getUserAttributes(
			@PathVariable("userId") String userId) {

		MainResponseDTO<Map<String, List<String>>> mainResponseDTO = new MainResponseDTO<Map<String, List<String>>>();

		mainResponseDTO.setVersion(String.valueOf(version));
		mainResponseDTO.setResponsetime(DateTimeFormatter.ofPattern(appDateTimeFormat).format(LocalDateTime.now()));

		List<ExceptionJSONInfoDTO> explist = new ArrayList<ExceptionJSONInfoDTO>();
		ExceptionJSONInfoDTO exception = new ExceptionJSONInfoDTO();

		try {

			mainResponseDTO.setResponse(kcAdminClient.getUserAttributes(userId));

		} catch (BadRequestException e) {
			// message = e.getMessage();
			exception.setMessage(e.getMessage());
			explist.add(exception);
			mainResponseDTO.setErrors(explist);
		}

		return ResponseEntity.status(HttpStatus.OK).body(mainResponseDTO);
	}

	@GetMapping("/")
	@RequiresAuth
	public ResponseEntity<?> getAllUsers() {
		return ResponseEntity.status(HttpStatus.OK).body(kcAdminClient.listUsersByClientId());
	}

	@GetMapping("/roles")
	@RequiresAuth
	public ResponseEntity<?> getAllRoles() {
		return ResponseEntity.status(HttpStatus.OK).body(kcAdminClient.listRolesByClientId());
	}

	@DeleteMapping("/{emailId}")
	@RequiresAuth
	public ResponseEntity<?> deleteUser(@PathVariable("emailId") String emailId) {
		return ResponseEntity.status(HttpStatus.OK).body(kcAdminClient.deleteUserByEmail(emailId));
	}

	/*
	 * @PostMapping("/logout") public ResponseEntity<?> logout(HttpServletRequest
	 * request, HttpServletResponse response) {
	 * 
	 * HttpSession session = request.getSession(false); if
	 * (request.isRequestedSessionIdValid() && session != null) {
	 * session.invalidate(); Cookie cookie = new Cookie("JSESSIONID", null);
	 * cookie.setPath("/"); cookie.setHttpOnly(true); cookie.setMaxAge(0);
	 * response.addCookie(cookie);
	 * 
	 * return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
	 * .body("You've been signed out!");
	 * 
	 * } return ResponseEntity.status(HttpStatus.BAD_REQUEST).
	 * body("No valid session found to logout."); }
	 * 
	 * private boolean isValidToken(String token) { return
	 * kcAdminClient.validateToken(token.replace("Bearer ", "")); }
	 */

}
