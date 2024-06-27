package org.api.dto.user;

import lombok.Data;

@Data
public class UpdateRequest {
  private String email;
  private String username;
  private String password;
  private String image;
  private String bio;
}
