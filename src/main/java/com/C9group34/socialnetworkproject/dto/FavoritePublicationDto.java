package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import lombok.Builder;
import lombok.Getter;

import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
public class FavoritePublicationDto {

    private int id;
    private Integer userId;
    private Integer publicationId;
}
