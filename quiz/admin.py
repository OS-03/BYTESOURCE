from django.contrib import admin
from django import forms
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.admin import AdminSite
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import Profile, Quiz, Category, Question, Progress, CSVUpload
from mcq.models import MCQQuestion, Answer
from cloudinary.uploader import upload


class CSVUploadsAdmin(admin.ModelAdmin):
    model = CSVUpload
    list_display = ("title",)


class AnswerInline(admin.TabularInline):
    model = Answer


class QuizAdminForm(forms.ModelForm):
    """
    below is from
    http://stackoverflow.com/questions/11657682/
    django-admin-interface-using-horizontal-filter-with-
    inline-manytomany-field
    """

    class Meta:
        model = Quiz
        exclude = []

    questions = forms.ModelMultipleChoiceField(
        queryset=Question.objects.all().select_subclasses(),
        required=False,
        label=_("Questions"),
        widget=FilteredSelectMultiple(verbose_name=_("Questions"), is_stacked=False),
    )

    def __init__(self, *args, **kwargs):
        super(QuizAdminForm, self).__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["questions"].initial = (
                self.instance.question_set.all().select_subclasses()
            )

    def save(self, commit=True):
        quiz = super(QuizAdminForm, self).save(commit=False)
        quiz.save()
        quiz.question_set.set(self.cleaned_data["questions"])
        self.save_m2m()
        return quiz


class QuizAdmin(admin.ModelAdmin):
    form = QuizAdminForm

    list_display = (
        "title",
        "category",
    )
    list_filter = ("category",)
    search_fields = (
        "description",
        "category",
    )


class CategoryAdmin(admin.ModelAdmin):
    search_fields = ("category",)


class MCQuestionAdmin(admin.ModelAdmin):
    list_display = (
        "content",
        "category",
    )
    list_filter = ("category",)
    fields = ("content", "category", "figure", "quiz", "explanation", "answer_order")

    search_fields = ("content", "explanation")
    filter_horizontal = ("quiz",)

    inlines = [AnswerInline]


class ProgressAdmin(admin.ModelAdmin):
    """
    to do:
            create a user section
    """

    search_fields = (
        "user",
        "score",
    )


class CustomAdminSite(AdminSite):
    site_header = _("Admin or Staff Login")
    site_title = _("Admin or Staff Login")
    index_title = _("Welcome to the Admin or Staff Portal")

    def login(self, request, extra_context=None):
        extra_context = extra_context or {}
        # extra_context['redirect_url'] = reverse('main-page')
        return super().login(request, extra_context)


class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = "profiles"


class UserAdmin(BaseUserAdmin):
    inlines = (ProfileInline,)

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(UserAdmin, self).get_inline_instances(request, obj)

class ProfileAdmin(admin.ModelAdmin):
    def save_model(self, request, obj, form, change):
        if 'image' in request.FILES:
            uploaded_image = upload(request.FILES['image'])
            obj.image = uploaded_image['url']
        super().save_model(request, obj, form, change)


# admin.site.register(Quiz, QuizAdmin)
# admin.site.register(Category, CategoryAdmin)
# admin.site.register(MCQQuestion, MCQuestionAdmin)
# admin.site.register(Progress, ProgressAdmin)
# admin.site.register(CSVUpload, CSVUploadsAdmin)
# admin.site.register(Profile)
custom_admin_site = CustomAdminSite(name="custom_admin")
custom_admin_site.register(User, UserAdmin)
custom_admin_site.register(Profile, ProfileAdmin)
custom_admin_site.register(Quiz, QuizAdmin)
custom_admin_site.register(Category, CategoryAdmin)
custom_admin_site.register(MCQQuestion, MCQuestionAdmin)
custom_admin_site.register(Progress, ProgressAdmin)
custom_admin_site.register(CSVUpload, CSVUploadsAdmin)
custom_admin_site.register(Answer)
