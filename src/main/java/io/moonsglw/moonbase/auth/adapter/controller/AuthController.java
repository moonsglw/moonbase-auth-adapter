package io.moonsglw.moonbase.auth.adapter.controller;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.moonsglw.moonbase.auth.adapter.dto.MainResponseDTO;
import io.moonsglw.moonbase.auth.adapter.dto.TokenResponseDTO;
import io.moonsglw.moonbase.auth.adapter.dto.request.AuthRequestDTO;
import io.moonsglw.moonbase.auth.adapter.service.KeycloakService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private KeycloakService keycloakService;

	@PostMapping("/token")
	public ResponseEntity<MainResponseDTO<TokenResponseDTO>> authenticate(@RequestBody AuthRequestDTO authRequest) {

		TokenResponseDTO tokenResponse = keycloakService.getToken(authRequest.getClientId(),
				authRequest.getClientSecret());
		MainResponseDTO<TokenResponseDTO> response = new MainResponseDTO<TokenResponseDTO>();
		response.setResponse(tokenResponse);

		return ResponseEntity.ok(response);
	}

}
