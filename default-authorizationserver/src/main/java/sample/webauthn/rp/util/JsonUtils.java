package sample.webauthn.rp.util;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

public class JsonUtils {
  private static final ObjectMapper mapper;

  static {
    mapper = new ObjectMapper();

    mapper.registerModule(new ParameterNamesModule());
    mapper.registerModule(new Jdk8Module());
    mapper.registerModule(new JavaTimeModule());

    mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
  }

  private JsonUtils() {}

  public static String format(String json) {
    return toJson(fromJson(json, Object.class));
  }

  public static <T> T fromJson(String json, Class<T> type) {
    try {
      return mapper.readValue(json, type);
    } catch (IOException e) {
      throw new JsonUtilsException(
          String.format(
              "Unable to parse json value into java object of type '%s' using jackson ObjectMapper",
              type.getName()),
          e);
    }
  }

  public static String toJson(Object object) {
    try {
      return mapper.writeValueAsString(object);
    } catch (JsonProcessingException e) {
      throw new JsonUtilsException(
          String.format(
              "Unable to convert Java object of type '%s' to json using jackson ObjectMapper",
              object.getClass().getName()),
          e);
    }
  }
}
