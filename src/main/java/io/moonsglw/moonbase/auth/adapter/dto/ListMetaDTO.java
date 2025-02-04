package io.moonsglw.moonbase.auth.adapter.dto;

import java.util.List;

import lombok.Data;

@Data
public class ListMetaDTO<T> {

	private List<T> recordsList;
	private int totalRecords;
	
}
