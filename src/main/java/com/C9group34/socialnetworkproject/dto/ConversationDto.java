package com.C9group34.socialnetworkproject.dto;

import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@ToString
public class ConversationDto {
    private int id;
    private String title;
    private int creator_id;

}

