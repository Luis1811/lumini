package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class CommentDto {
    private int id;
    private String content;
    private User user;
    private Publication publication;

}
