package com.C9group34.socialnetworkproject.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class ConversationDto {
    private int id;
    private String title;
    private int creator_id;

}

