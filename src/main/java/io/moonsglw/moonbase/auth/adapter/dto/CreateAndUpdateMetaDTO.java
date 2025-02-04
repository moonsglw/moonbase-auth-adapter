package io.moonsglw.moonbase.auth.adapter.dto;

import lombok.Data;

@Data
public class CreateAndUpdateMetaDTO<T> {
	
	private String id;
	private boolean status;
	private T data; 
	
}
