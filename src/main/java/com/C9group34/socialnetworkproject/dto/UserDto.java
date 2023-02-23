package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.Publication;

import com.C9group34.socialnetworkproject.models.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class UserDto {
    private Integer id;

    private String name;

    private String surname;

    private String email;

    private String phone;

    private String password;

    private Double ratings;


    private List<Role> roles;

    private List<Publication> publications;

}
