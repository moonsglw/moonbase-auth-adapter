package io.moonsglw.moonbase.auth.adapter.dto.request;

import java.util.List;
import java.util.Map;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class UserRequestDTO {
	String username;
	String password;
	String email;
	String firstname;
	String lastname;
	String role;
	boolean enabled;
	Map<String, List<String>> attributes;
}
