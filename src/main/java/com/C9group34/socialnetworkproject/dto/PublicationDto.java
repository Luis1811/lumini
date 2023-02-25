package com.C9group34.socialnetworkproject.dto;


import jakarta.persistence.*;
import lombok.*;


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
    private String status;
    private List<CommentDto> comments;

}
