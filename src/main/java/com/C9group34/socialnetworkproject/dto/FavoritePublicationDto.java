package com.C9group34.socialnetworkproject.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Builder;
import lombok.Getter;

import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import lombok.*;


import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@Getter
public class FavoritePublicationDto {

    private int id;
    private User user;
    private Publication publication;
}
