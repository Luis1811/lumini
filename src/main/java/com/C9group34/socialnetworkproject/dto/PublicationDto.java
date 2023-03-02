package com.C9group34.socialnetworkproject.dto;


import lombok.*;


import java.io.File;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@ToString
public class PublicationDto {

    private Integer id;
    private String title;
    private String description;
    private String urlImg;
    private Double rating;
    private String userImgProfile;
    private List<CommentDto> comments;
    private Integer category;

}
