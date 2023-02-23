package com.C9group34.socialnetworkproject.Request;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;

@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@JsonPropertyOrder({ "content", "sender", "user", "title" })
public class ConversationRequest {
    @JsonProperty("content")
    private String content;
    @JsonProperty("sender")
    private Integer sender;
    @JsonProperty("user")
    private Integer user;
    @JsonProperty("title")
    private String title;

}
