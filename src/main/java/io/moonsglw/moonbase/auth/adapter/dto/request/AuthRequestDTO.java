package io.moonsglw.moonbase.auth.adapter.dto.request;

import lombok.Data;

@Data
public class AuthRequestDTO {
	
	private String clientId;
    private String clientSecret;
}
