package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.Conversation;
import com.C9group34.socialnetworkproject.models.FavoritePublication;
import com.C9group34.socialnetworkproject.models.Publication;

import com.C9group34.socialnetworkproject.models.Role;
import lombok.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@ToString
public class UserDto {
    private Integer id;
    private String name;
    private String surname;
    private String email;
    private String phone;
    private File imgProfile;
    private String password;
    private Double ratings;
    private List<Role> roles;
    private List<Publication> publications = new ArrayList<>();
    private List<FavoritePublication> favoritePublications = new ArrayList<>();
    private List<Conversation> conversations = new ArrayList<>();

}
