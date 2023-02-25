package com.C9group34.socialnetworkproject.dto;

import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@ToString
public class CommentDto {

    private int id;
    private String content;

}
