package io.moonsglw.moonbase.auth.adapter.util;

import java.util.Collection;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class EmptyNullCheckUtil {
	
	public static boolean isNullEmpty(Object obj) {
		return obj == null;
	}

	/**
	 * This method is used to check if the given <code>str</code> is null or an
	 * empty string.
	 * 
	 * @param str id of type java.lang.String
	 * @return true if given <code>str</code> is null or length of it is Zero after
	 *         trim.
	 */
	public static boolean isNullEmpty(String str) {
		return str == null || str.trim().length() == 0;
	}

	/**
	 * This method is used to check given <code>collection</code> is null or is
	 * Empty.
	 * 
	 * @param collection is of type java.util.Collection.
	 * @return true if given <code>collection</code> is null or does not contains
	 *         any element inside it.
	 */
	public static boolean isNullEmpty(Collection<?> collection) {
		return collection == null || collection.isEmpty();
	}

	/**
	 * This method is used to check given <code>byte[]</code> is null or is Empty.
	 * 
	 * @param array of type byte.
	 * @return true if given <code>byte[]</code> is null or does not contains any
	 *         element inside it.
	 */
	public static boolean isNullEmpty(byte[] array) {
		return array == null || array.length == 0;
	}

	/**
	 * This method is used to check given <code>map</code> is null or is Empty.
	 * 
	 * @param map is of type java.util.Map
	 * @return true if given <code>map</code> is null or does not contains any key,
	 *         values pairs inside it.
	 */
	public static boolean isNullEmpty(Map<?, ?> map) {
		return map == null || map.isEmpty();
	}
}
