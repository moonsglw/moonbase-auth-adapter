package io.moonsglw.moonbase.auth.adapter.dto;

import java.io.Serializable;
import java.util.List;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class MainResponseDTO<T> implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String id;
	private String version;
	private String responsetime;
	private T response;
	
	/** The error details. */
	private List<ExceptionJSONInfoDTO> errors;
}
