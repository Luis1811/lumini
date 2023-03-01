package com.C9group34.socialnetworkproject.service;

import com.C9group34.socialnetworkproject.dto.CommentDto;
import com.C9group34.socialnetworkproject.models.Publication;
import lombok.*;

import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class PublicationDtoo {

    private Integer id;
    private String title;
    private String description;
    private String img;
    private Double rating;
    private List<CommentDto> comments;
    private Integer category;
    public PublicationDtoo(Publication publication, String urlImg) {
    }
}
