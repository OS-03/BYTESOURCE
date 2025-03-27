from django.urls import include, re_path, path
from .views import *


urlpatterns = [
    re_path(r"^$", view=index, name="index"),
    re_path(r"^login$", view=login_user, name="login"),
    re_path(r"^dsa/$", view=dsa, name="dsa"),
    re_path(r"^dsa1/$", view=dsa1, name="dsa1"),
    re_path(r"^dsa2/$", view=dsa2, name="dsa2"),
    re_path(r"^dsa3/$", view=dsa3, name="dsa3"),
    re_path(r"^dsa4/$", view=dsa4, name="dsa4"),
    re_path(r"^dsa5/$", view=dsa5, name="dsa5"),
    re_path(r"^dsa6/$", view=dsa6, name="dsa6"),
    re_path(r"^os/$", view=os, name="os"),
    re_path(r"^os1/$", view=os1, name="os1"),
    re_path(r"^os2/$", view=os2, name="os2"),
    re_path(r"^os3/$", view=os3, name="os3"),
    re_path(r"^os4/$", view=os4, name="os4"),
    re_path(r"^os5/$", view=os5, name="os5"),
    re_path(r"^sql/$", view=sql, name="sql"),
    re_path(r"^sql1/$", view=sql1, name="sql1"),
    re_path(r"^sql2/$", view=sql2, name="sql2"),
    re_path(r"^sql3/$", view=sql3, name="sql3"),
    re_path(r"^sql4/$", view=sql4, name="sql4"),
    re_path(r"^sql5/$", view=sql5, name="sql5"),
    re_path(r"^toc/$", view=toc, name="toc"),
    re_path(r"^toc1/$", view=toc1, name="toc1"),
    re_path(r"^toc2/$", view=toc2, name="toc2"),
    re_path(r"^toc3/$", view=toc3, name="toc3"),
    re_path(r"^toc4/$", view=toc4, name="toc4"),
    re_path(r"^toc5/$", view=toc5, name="toc5"),
    re_path(r"^cn/$", view=cn, name="cn"),
    re_path(r"^cn1/$", view=cn1, name="cn1"),
    re_path(r"^cn2/$", view=cn2, name="cn2"),
    re_path(r"^cn3/$", view=cn3, name="cn3"),
    re_path(r"^cn4/$", view=cn4, name="cn4"),
    re_path(r"^cn5/$", view=cn5, name="cn5"),
    re_path(r"^cn6/$", view=cn6, name="cn6"),
    re_path(r"^signup$", view=signup_user, name="signup"),
    re_path(r"^Go/$", view=Go, name="Go"),
    re_path(r"^logout/$", view=logout_user, name="logout"),
    re_path(r"^quizzes/$", view=QuizListView.as_view(), name="quiz_index"),
    re_path(
        r"^category/$", view=CategoriesListView.as_view(), name="quiz_category_list_all"
    ),
    re_path(
        r"^category/(?P<category_name>[\w|\W-]+)/$",
        view=ViewQuizListByCategory.as_view(),
        name="quiz_category_list_matching",
    ),
    re_path(r"^progress/$", view=QuizUserProgressView.as_view(), name="quiz_progress"),
    re_path(r"^marking/$", view=QuizMarkingList.as_view(), name="quiz_marking"),
    re_path(
        r"^marking/(?P<pk>[\d.]+)/$",
        view=QuizMarkingDetail.as_view(),
        name="quiz_marking_detail",
    ),
    #  passes variable 'quiz_name' to quiz_take view
    re_path(
        r"^(?P<slug>[\w-]+)/$", view=QuizDetailView.as_view(), name="quiz_start_page"
    ),
    re_path(
        r"^(?P<quiz_name>[\w-]+)/take/$", view=QuizTake.as_view(), name="quiz_question"
    ),
    re_path(
        r"^quiz/redirect_to_admin/$", view=redirect_to_admin, name="redirect_to_admin"
    ),
    re_path(r"^admin$", view=admin, name="admin"),
]
